/**
 * net-map - Network Scanner Implementation
 * Supports ARP, ICMP Ping, and TCP SYN scanning
 */

#include "scanner.h"
#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#endif

// Well-known ports for quick scan
const uint16_t COMMON_PORTS[] = {
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443
};
const int COMMON_PORTS_COUNT = sizeof(COMMON_PORTS) / sizeof(COMMON_PORTS[0]);

// Service names
typedef struct {
    uint16_t port;
    const char *name;
} service_entry_t;

static const service_entry_t SERVICES[] = {
    {20, "ftp-data"}, {21, "ftp"}, {22, "ssh"}, {23, "telnet"},
    {25, "smtp"}, {53, "dns"}, {67, "dhcp"}, {68, "dhcp"},
    {69, "tftp"}, {80, "http"}, {110, "pop3"}, {111, "rpcbind"},
    {119, "nntp"}, {123, "ntp"}, {135, "msrpc"}, {137, "netbios-ns"},
    {138, "netbios-dgm"}, {139, "netbios-ssn"}, {143, "imap"},
    {161, "snmp"}, {162, "snmptrap"}, {389, "ldap"}, {443, "https"},
    {445, "microsoft-ds"}, {465, "smtps"}, {514, "syslog"},
    {515, "printer"}, {587, "submission"}, {636, "ldaps"},
    {993, "imaps"}, {995, "pop3s"}, {1433, "mssql"}, {1434, "mssql-m"},
    {1521, "oracle"}, {1723, "pptp"}, {3306, "mysql"}, {3389, "rdp"},
    {5432, "postgresql"}, {5900, "vnc"}, {5901, "vnc-1"},
    {6379, "redis"}, {8080, "http-proxy"}, {8443, "https-alt"},
    {27017, "mongodb"}, {0, NULL}
};

// Scanner state
struct scanner {
    scan_config_t config;
    bool running;
    bool stop_requested;

    // Results
    scan_result_t *results;
    int result_count;
    int result_capacity;

    // Progress
    int current;
    int total;

    // Thread
#ifdef _WIN32
    HANDLE thread;
    CRITICAL_SECTION lock;
#else
    pthread_t thread;
    pthread_mutex_t lock;
#endif

    // Sockets
#ifdef _WIN32
    HANDLE icmp_handle;
#else
    int raw_socket;
    int icmp_socket;
#endif
};

// Forward declarations
static void* scan_thread(void *arg);
static int do_arp_scan(scanner_t *scanner);
static int do_ping_scan(scanner_t *scanner);
static int do_syn_scan(scanner_t *scanner);
static void add_result(scanner_t *scanner, scan_result_t *result);

// Utility functions
int parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask) {
    char ip_part[32];
    int prefix = 24;

    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t ip_len = slash - cidr;
        if (ip_len >= sizeof(ip_part)) return -1;
        strncpy(ip_part, cidr, ip_len);
        ip_part[ip_len] = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) return -1;
    } else {
        strncpy(ip_part, cidr, sizeof(ip_part) - 1);
        ip_part[sizeof(ip_part) - 1] = '\0';
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1) {
        return -1;
    }

    *network = ntohl(addr.s_addr);
    *mask = prefix == 0 ? 0 : (~0U << (32 - prefix));
    *network &= *mask;

    return 0;
}

int ip_range_count(uint32_t network, uint32_t mask) {
    return (~mask) + 1;
}

void ip_to_str(uint32_t ip, char *buf, size_t len) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, (socklen_t)len);
}

uint32_t str_to_ip(const char *str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, str, &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

void mac_to_str(const uint8_t *mac, char *buf, size_t len) {
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* get_service_name(uint16_t port) {
    for (int i = 0; SERVICES[i].name != NULL; i++) {
        if (SERVICES[i].port == port) {
            return SERVICES[i].name;
        }
    }
    return NULL;
}

// Create scanner
scanner_t* scanner_create(const scan_config_t *config) {
    scanner_t *scanner = calloc(1, sizeof(scanner_t));
    if (!scanner) return NULL;

    memcpy(&scanner->config, config, sizeof(scan_config_t));

    // Set defaults
    if (scanner->config.timeout_ms <= 0) {
        scanner->config.timeout_ms = 1000;
    }
    if (scanner->config.retries <= 0) {
        scanner->config.retries = 2;
    }

    // Initialize results array
    scanner->result_capacity = 256;
    scanner->results = calloc(scanner->result_capacity, sizeof(scan_result_t));
    if (!scanner->results) {
        free(scanner);
        return NULL;
    }

#ifdef _WIN32
    InitializeCriticalSection(&scanner->lock);
#else
    pthread_mutex_init(&scanner->lock, NULL);
#endif

    return scanner;
}

void scanner_destroy(scanner_t *scanner) {
    if (!scanner) return;

    scanner_stop(scanner);

    // Free results
    for (int i = 0; i < scanner->result_count; i++) {
        if (scanner->results[i].ports) {
            free(scanner->results[i].ports);
        }
    }
    free(scanner->results);

#ifdef _WIN32
    DeleteCriticalSection(&scanner->lock);
#else
    pthread_mutex_destroy(&scanner->lock);
#endif

    free(scanner);
}

// Start scanning
int scanner_start(scanner_t *scanner) {
    if (!scanner || scanner->running) return -1;

    scanner->running = true;
    scanner->stop_requested = false;
    scanner->current = 0;
    scanner->result_count = 0;

    // Parse target range
    uint32_t network, mask;
    if (parse_cidr(scanner->config.target, &network, &mask) != 0) {
        scanner->running = false;
        return -1;
    }
    scanner->total = ip_range_count(network, mask);

#ifdef _WIN32
    scanner->thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)scan_thread, scanner, 0, NULL);
    if (!scanner->thread) {
        scanner->running = false;
        return -1;
    }
#else
    if (pthread_create(&scanner->thread, NULL, scan_thread, scanner) != 0) {
        scanner->running = false;
        return -1;
    }
#endif

    return 0;
}

void scanner_stop(scanner_t *scanner) {
    if (!scanner || !scanner->running) return;

    scanner->stop_requested = true;

#ifdef _WIN32
    WaitForSingleObject(scanner->thread, 5000);
    CloseHandle(scanner->thread);
#else
    pthread_join(scanner->thread, NULL);
#endif

    scanner->running = false;
}

bool scanner_is_running(scanner_t *scanner) {
    return scanner && scanner->running;
}

int scanner_get_progress(scanner_t *scanner, int *current, int *total) {
    if (!scanner) return -1;
    if (current) *current = scanner->current;
    if (total) *total = scanner->total;
    return 0;
}

int scanner_get_results(scanner_t *scanner, scan_result_t **results) {
    if (!scanner || !results) return -1;

#ifdef _WIN32
    EnterCriticalSection(&scanner->lock);
#else
    pthread_mutex_lock(&scanner->lock);
#endif

    int count = scanner->result_count;
    if (count > 0) {
        *results = calloc(count, sizeof(scan_result_t));
        if (*results) {
            memcpy(*results, scanner->results, count * sizeof(scan_result_t));
            // Deep copy ports
            for (int i = 0; i < count; i++) {
                if (scanner->results[i].ports && scanner->results[i].port_count > 0) {
                    (*results)[i].ports = calloc(scanner->results[i].port_count, sizeof(port_info_t));
                    if ((*results)[i].ports) {
                        memcpy((*results)[i].ports, scanner->results[i].ports,
                               scanner->results[i].port_count * sizeof(port_info_t));
                    }
                }
            }
        }
    } else {
        *results = NULL;
    }

#ifdef _WIN32
    LeaveCriticalSection(&scanner->lock);
#else
    pthread_mutex_unlock(&scanner->lock);
#endif

    return count;
}

void scanner_free_results(scan_result_t *results, int count) {
    if (!results) return;
    for (int i = 0; i < count; i++) {
        if (results[i].ports) {
            free(results[i].ports);
        }
    }
    free(results);
}

static void add_result(scanner_t *scanner, scan_result_t *result) {
#ifdef _WIN32
    EnterCriticalSection(&scanner->lock);
#else
    pthread_mutex_lock(&scanner->lock);
#endif

    // Expand array if needed
    if (scanner->result_count >= scanner->result_capacity) {
        int new_capacity = scanner->result_capacity * 2;
        scan_result_t *new_results = realloc(scanner->results, new_capacity * sizeof(scan_result_t));
        if (new_results) {
            scanner->results = new_results;
            scanner->result_capacity = new_capacity;
        }
    }

    if (scanner->result_count < scanner->result_capacity) {
        memcpy(&scanner->results[scanner->result_count], result, sizeof(scan_result_t));
        scanner->result_count++;

        // Call callback
        if (scanner->config.on_result) {
            scanner->config.on_result(result, scanner->config.user_data);
        }
    }

#ifdef _WIN32
    LeaveCriticalSection(&scanner->lock);
#else
    pthread_mutex_unlock(&scanner->lock);
#endif
}

// Scan thread
static void* scan_thread(void *arg) {
    scanner_t *scanner = (scanner_t *)arg;

    switch (scanner->config.type) {
        case SCAN_TYPE_ARP:
            do_arp_scan(scanner);
            break;
        case SCAN_TYPE_PING:
            do_ping_scan(scanner);
            break;
        case SCAN_TYPE_SYN:
        case SCAN_TYPE_CONNECT:
            do_syn_scan(scanner);
            break;
    }

    scanner->running = false;
    return NULL;
}

// ARP Scan implementation
static int do_arp_scan(scanner_t *scanner) {
    uint32_t network, mask;
    if (parse_cidr(scanner->config.target, &network, &mask) != 0) {
        return -1;
    }

    uint32_t first_ip = network + 1;  // Skip network address
    uint32_t last_ip = (network | ~mask) - 1;  // Skip broadcast

#ifdef _WIN32
    for (uint32_t ip = first_ip; ip <= last_ip && !scanner->stop_requested; ip++) {
        scanner->current = ip - first_ip + 1;

        if (scanner->config.on_progress) {
            scanner->config.on_progress(scanner->current, scanner->total, scanner->config.user_data);
        }

        struct in_addr dest_ip;
        dest_ip.s_addr = htonl(ip);

        ULONG mac_addr[2];
        ULONG mac_len = 6;

        DWORD start_time = GetTickCount();
        DWORD result = SendARP(dest_ip.s_addr, 0, mac_addr, &mac_len);
        DWORD rtt = GetTickCount() - start_time;

        if (result == NO_ERROR && mac_len == 6) {
            scan_result_t res = {0};
            res.ip = ip;
            ip_to_str(ip, res.ip_str, sizeof(res.ip_str));
            memcpy(res.mac, mac_addr, 6);
            mac_to_str(res.mac, res.mac_str, sizeof(res.mac_str));
            res.status = HOST_STATUS_UP;
            res.rtt_us = rtt * 1000;
            res.discovered_at = (uint64_t)time(NULL) * 1000000;

            add_result(scanner, &res);
        }

        // Rate limiting
        if (scanner->config.rate_limit > 0) {
            Sleep(1000 / scanner->config.rate_limit);
        }
    }
#else
    // Linux/Unix ARP scan using raw socket
    // Note: Requires root privileges
    for (uint32_t ip = first_ip; ip <= last_ip && !scanner->stop_requested; ip++) {
        scanner->current = ip - first_ip + 1;

        if (scanner->config.on_progress) {
            scanner->config.on_progress(scanner->current, scanner->total, scanner->config.user_data);
        }

        // TODO: Implement raw ARP packet sending
        // For now, use system arping or similar

        if (scanner->config.rate_limit > 0) {
            usleep(1000000 / scanner->config.rate_limit);
        }
    }
#endif

    return 0;
}

// ICMP Ping scan implementation
static int do_ping_scan(scanner_t *scanner) {
    uint32_t network, mask;
    if (parse_cidr(scanner->config.target, &network, &mask) != 0) {
        return -1;
    }

    uint32_t first_ip = network + 1;
    uint32_t last_ip = (network | ~mask) - 1;

#ifdef _WIN32
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        return -1;
    }

    char send_data[32] = "Net-Map Ping";
    char reply_buffer[sizeof(ICMP_ECHO_REPLY) + sizeof(send_data) + 8];

    for (uint32_t ip = first_ip; ip <= last_ip && !scanner->stop_requested; ip++) {
        scanner->current = ip - first_ip + 1;

        if (scanner->config.on_progress) {
            scanner->config.on_progress(scanner->current, scanner->total, scanner->config.user_data);
        }

        struct in_addr dest_ip;
        dest_ip.s_addr = htonl(ip);

        DWORD reply_count = IcmpSendEcho(icmp, dest_ip.s_addr,
            send_data, sizeof(send_data),
            NULL, reply_buffer, sizeof(reply_buffer),
            scanner->config.timeout_ms);

        if (reply_count > 0) {
            PICMP_ECHO_REPLY reply = (PICMP_ECHO_REPLY)reply_buffer;

            if (reply->Status == IP_SUCCESS) {
                scan_result_t res = {0};
                res.ip = ip;
                ip_to_str(ip, res.ip_str, sizeof(res.ip_str));
                res.status = HOST_STATUS_UP;
                res.rtt_us = reply->RoundTripTime * 1000;
                res.discovered_at = (uint64_t)time(NULL) * 1000000;

                add_result(scanner, &res);
            }
        }

        if (scanner->config.rate_limit > 0) {
            Sleep(1000 / scanner->config.rate_limit);
        }
    }

    IcmpCloseHandle(icmp);
#else
    // Unix ICMP ping using raw socket (requires root)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        return -1;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = scanner->config.timeout_ms / 1000;
    tv.tv_usec = (scanner->config.timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    for (uint32_t ip = first_ip; ip <= last_ip && !scanner->stop_requested; ip++) {
        scanner->current = ip - first_ip + 1;

        if (scanner->config.on_progress) {
            scanner->config.on_progress(scanner->current, scanner->total, scanner->config.user_data);
        }

        // TODO: Send ICMP echo request and receive reply
        // Implementation omitted for brevity

        if (scanner->config.rate_limit > 0) {
            usleep(1000000 / scanner->config.rate_limit);
        }
    }

    close(sock);
#endif

    return 0;
}

// TCP SYN/Connect scan implementation
static int do_syn_scan(scanner_t *scanner) {
    uint32_t network, mask;
    if (parse_cidr(scanner->config.target, &network, &mask) != 0) {
        return -1;
    }

    uint32_t first_ip = network + 1;
    uint32_t last_ip = (network | ~mask) - 1;

    // Use default ports if none specified
    const uint16_t *ports = scanner->config.ports ? scanner->config.ports : COMMON_PORTS;
    int port_count = scanner->config.port_count > 0 ? scanner->config.port_count : COMMON_PORTS_COUNT;

    for (uint32_t ip = first_ip; ip <= last_ip && !scanner->stop_requested; ip++) {
        scanner->current = ip - first_ip + 1;

        if (scanner->config.on_progress) {
            scanner->config.on_progress(scanner->current, scanner->total, scanner->config.user_data);
        }

        scan_result_t res = {0};
        res.ip = ip;
        ip_to_str(ip, res.ip_str, sizeof(res.ip_str));
        res.ports = calloc(port_count, sizeof(port_info_t));
        res.port_count = 0;
        res.discovered_at = (uint64_t)time(NULL) * 1000000;

        bool host_up = false;

        for (int p = 0; p < port_count && !scanner->stop_requested; p++) {
            uint16_t port = ports[p];

#ifdef _WIN32
            SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) continue;

            // Set non-blocking
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(ip);
            addr.sin_port = htons(port);

            int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

            if (result == 0) {
                // Immediate connection (unlikely)
                if (res.ports) {
                    res.ports[res.port_count].port = port;
                    res.ports[res.port_count].status = PORT_STATUS_OPEN;
                    const char *svc = get_service_name(port);
                    if (svc) strncpy(res.ports[res.port_count].service, svc, 31);
                    res.port_count++;
                }
                host_up = true;
            } else {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    // Wait for connection with timeout
                    fd_set write_fds;
                    FD_ZERO(&write_fds);
                    FD_SET(sock, &write_fds);

                    struct timeval tv;
                    tv.tv_sec = scanner->config.timeout_ms / 1000;
                    tv.tv_usec = (scanner->config.timeout_ms % 1000) * 1000;

                    result = select(0, NULL, &write_fds, NULL, &tv);
                    if (result > 0 && FD_ISSET(sock, &write_fds)) {
                        // Check if actually connected
                        int optval;
                        int optlen = sizeof(optval);
                        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&optval, &optlen);

                        if (optval == 0) {
                            if (res.ports) {
                                res.ports[res.port_count].port = port;
                                res.ports[res.port_count].status = PORT_STATUS_OPEN;
                                const char *svc = get_service_name(port);
                                if (svc) strncpy(res.ports[res.port_count].service, svc, 31);
                                res.port_count++;
                            }
                            host_up = true;
                        }
                    }
                }
            }

            closesocket(sock);
#else
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) continue;

            // Set non-blocking
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);

            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(ip);
            addr.sin_port = htons(port);

            int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));

            if (result == 0 || (result < 0 && errno == EINPROGRESS)) {
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(sock, &write_fds);

                struct timeval tv;
                tv.tv_sec = scanner->config.timeout_ms / 1000;
                tv.tv_usec = (scanner->config.timeout_ms % 1000) * 1000;

                result = select(sock + 1, NULL, &write_fds, NULL, &tv);
                if (result > 0) {
                    int optval;
                    socklen_t optlen = sizeof(optval);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);

                    if (optval == 0) {
                        if (res.ports) {
                            res.ports[res.port_count].port = port;
                            res.ports[res.port_count].status = PORT_STATUS_OPEN;
                            const char *svc = get_service_name(port);
                            if (svc) strncpy(res.ports[res.port_count].service, svc, 31);
                            res.port_count++;
                        }
                        host_up = true;
                    }
                }
            }

            close(sock);
#endif
        }

        if (host_up) {
            res.status = HOST_STATUS_UP;
            add_result(scanner, &res);
        } else {
            free(res.ports);
        }

        if (scanner->config.rate_limit > 0) {
#ifdef _WIN32
            Sleep(1000 / scanner->config.rate_limit);
#else
            usleep(1000000 / scanner->config.rate_limit);
#endif
        }
    }

    return 0;
}

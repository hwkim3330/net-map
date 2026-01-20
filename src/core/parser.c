/**
 * net-map - Protocol parser implementation
 */

#include "parser.h"
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// Ethernet types
#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_IPV6 0x86DD

// IP protocols
#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17

// Common ports
#define PORT_DNS   53
#define PORT_HTTP  80
#define PORT_HTTPS 443
#define PORT_DHCP_S 67
#define PORT_DHCP_C 68

void mac_to_string(const uint8_t *mac, char *str) {
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_to_string(uint32_t ip, char *str) {
    uint8_t *bytes = (uint8_t*)&ip;
    sprintf(str, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

const char* protocol_to_string(protocol_t proto) {
    switch (proto) {
        case PROTO_ETHERNET: return "Ethernet";
        case PROTO_ARP:      return "ARP";
        case PROTO_IPV4:     return "IPv4";
        case PROTO_IPV6:     return "IPv6";
        case PROTO_ICMP:     return "ICMP";
        case PROTO_TCP:      return "TCP";
        case PROTO_UDP:      return "UDP";
        case PROTO_DNS:      return "DNS";
        case PROTO_HTTP:     return "HTTP";
        case PROTO_HTTPS:    return "HTTPS";
        case PROTO_DHCP:     return "DHCP";
        default:             return "Unknown";
    }
}

static void parse_ethernet(const uint8_t *data, parsed_packet_t *result) {
    memcpy(result->eth.dst_mac, data, 6);
    memcpy(result->eth.src_mac, data + 6, 6);
    result->eth.ethertype = ntohs(*(uint16_t*)(data + 12));

    mac_to_string(result->eth.src_mac, result->src_mac_str);
    mac_to_string(result->eth.dst_mac, result->dst_mac_str);
}

static int parse_ipv4(const uint8_t *data, uint32_t len, parsed_packet_t *result) {
    if (len < 20) return -1;

    result->has_ip = true;
    result->ip.version = (data[0] >> 4) & 0x0F;
    result->ip.ihl = data[0] & 0x0F;
    result->ip.tos = data[1];
    result->ip.total_len = ntohs(*(uint16_t*)(data + 2));
    result->ip.id = ntohs(*(uint16_t*)(data + 4));
    result->ip.flags_offset = ntohs(*(uint16_t*)(data + 6));
    result->ip.ttl = data[8];
    result->ip.protocol = data[9];
    result->ip.checksum = ntohs(*(uint16_t*)(data + 10));
    memcpy(&result->ip.src_ip, data + 12, 4);
    memcpy(&result->ip.dst_ip, data + 16, 4);

    ip_to_string(result->ip.src_ip, result->src_ip_str);
    ip_to_string(result->ip.dst_ip, result->dst_ip_str);

    return result->ip.ihl * 4;
}

static void parse_tcp(const uint8_t *data, uint32_t len, parsed_packet_t *result) {
    if (len < 20) return;

    result->has_tcp = true;
    result->tcp.src_port = ntohs(*(uint16_t*)(data));
    result->tcp.dst_port = ntohs(*(uint16_t*)(data + 2));
    result->tcp.seq = ntohl(*(uint32_t*)(data + 4));
    result->tcp.ack = ntohl(*(uint32_t*)(data + 8));
    result->tcp.data_offset = (data[12] >> 4) & 0x0F;
    result->tcp.flags = data[13];
    result->tcp.window = ntohs(*(uint16_t*)(data + 14));
    result->tcp.checksum = ntohs(*(uint16_t*)(data + 16));
    result->tcp.urgent = ntohs(*(uint16_t*)(data + 18));

    uint32_t header_len = result->tcp.data_offset * 4;
    if (len > header_len) {
        result->payload = data + header_len;
        result->payload_len = len - header_len;
    }
}

static void parse_udp(const uint8_t *data, uint32_t len, parsed_packet_t *result) {
    if (len < 8) return;

    result->has_udp = true;
    result->udp.src_port = ntohs(*(uint16_t*)(data));
    result->udp.dst_port = ntohs(*(uint16_t*)(data + 2));
    result->udp.length = ntohs(*(uint16_t*)(data + 4));
    result->udp.checksum = ntohs(*(uint16_t*)(data + 6));

    if (len > 8) {
        result->payload = data + 8;
        result->payload_len = len - 8;
    }
}

static void detect_application_protocol(parsed_packet_t *result) {
    uint16_t src_port = 0, dst_port = 0;

    if (result->has_tcp) {
        src_port = result->tcp.src_port;
        dst_port = result->tcp.dst_port;
    } else if (result->has_udp) {
        src_port = result->udp.src_port;
        dst_port = result->udp.dst_port;
    }

    // Check well-known ports
    if (src_port == PORT_DNS || dst_port == PORT_DNS) {
        result->top_protocol = PROTO_DNS;
    } else if (src_port == PORT_HTTP || dst_port == PORT_HTTP) {
        result->top_protocol = PROTO_HTTP;
    } else if (src_port == PORT_HTTPS || dst_port == PORT_HTTPS) {
        result->top_protocol = PROTO_HTTPS;
    } else if (src_port == PORT_DHCP_S || dst_port == PORT_DHCP_S ||
               src_port == PORT_DHCP_C || dst_port == PORT_DHCP_C) {
        result->top_protocol = PROTO_DHCP;
    }
}

static void generate_info(parsed_packet_t *result) {
    if (result->has_tcp) {
        uint16_t src = result->tcp.src_port;
        uint16_t dst = result->tcp.dst_port;
        uint8_t flags = result->tcp.flags;

        char flag_str[32] = "";
        if (flags & 0x02) strcat(flag_str, "SYN ");
        if (flags & 0x10) strcat(flag_str, "ACK ");
        if (flags & 0x01) strcat(flag_str, "FIN ");
        if (flags & 0x04) strcat(flag_str, "RST ");
        if (flags & 0x08) strcat(flag_str, "PSH ");

        snprintf(result->info, sizeof(result->info),
                 "%d → %d [%s] Seq=%u Ack=%u Win=%u Len=%u",
                 src, dst, flag_str, result->tcp.seq, result->tcp.ack,
                 result->tcp.window, result->payload_len);
    } else if (result->has_udp) {
        snprintf(result->info, sizeof(result->info),
                 "%d → %d Len=%u",
                 result->udp.src_port, result->udp.dst_port, result->udp.length);
    } else if (result->has_ip) {
        snprintf(result->info, sizeof(result->info),
                 "TTL=%d Protocol=%d", result->ip.ttl, result->ip.protocol);
    } else {
        snprintf(result->info, sizeof(result->info),
                 "Ethertype=0x%04X", result->eth.ethertype);
    }
}

int parse_packet(const uint8_t *data, uint32_t len, parsed_packet_t *result) {
    if (!data || !result || len < 14) {
        return -1;
    }

    memset(result, 0, sizeof(parsed_packet_t));
    result->top_protocol = PROTO_ETHERNET;

    // Parse Ethernet
    parse_ethernet(data, result);
    data += 14;
    len -= 14;

    // Parse based on ethertype
    switch (result->eth.ethertype) {
        case ETH_TYPE_ARP:
            result->top_protocol = PROTO_ARP;
            strcpy(result->src_ip_str, result->src_mac_str);
            strcpy(result->dst_ip_str, result->dst_mac_str);
            snprintf(result->info, sizeof(result->info), "ARP Request/Reply");
            break;

        case ETH_TYPE_IPV4: {
            int ip_header_len = parse_ipv4(data, len, result);
            if (ip_header_len < 0) break;

            result->top_protocol = PROTO_IPV4;
            data += ip_header_len;
            len -= ip_header_len;

            switch (result->ip.protocol) {
                case IP_PROTO_ICMP:
                    result->top_protocol = PROTO_ICMP;
                    snprintf(result->info, sizeof(result->info), "ICMP");
                    break;

                case IP_PROTO_TCP:
                    parse_tcp(data, len, result);
                    result->top_protocol = PROTO_TCP;
                    break;

                case IP_PROTO_UDP:
                    parse_udp(data, len, result);
                    result->top_protocol = PROTO_UDP;
                    break;
            }
            break;
        }

        case ETH_TYPE_IPV6:
            result->top_protocol = PROTO_IPV6;
            strcpy(result->src_ip_str, "IPv6");
            strcpy(result->dst_ip_str, "IPv6");
            break;
    }

    // Detect application layer protocol
    detect_application_protocol(result);

    // Generate info string
    strcpy(result->protocol_str, protocol_to_string(result->top_protocol));
    if (result->info[0] == '\0') {
        generate_info(result);
    }

    return 0;
}

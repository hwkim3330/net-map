/**
 * net-map - Network Scanner Module
 * Implements ARP, ICMP Ping, and TCP SYN scanning
 */

#ifndef SCANNER_H
#define SCANNER_H

#include "platform.h"
#include <stdint.h>
#include <stdbool.h>

// Scan types
typedef enum {
    SCAN_TYPE_ARP,      // ARP scan (local network only)
    SCAN_TYPE_PING,     // ICMP echo scan
    SCAN_TYPE_SYN,      // TCP SYN scan
    SCAN_TYPE_CONNECT   // TCP connect scan
} scan_type_t;

// Host status
typedef enum {
    HOST_STATUS_UNKNOWN,
    HOST_STATUS_UP,
    HOST_STATUS_DOWN,
    HOST_STATUS_FILTERED
} host_status_t;

// Port status
typedef enum {
    PORT_STATUS_UNKNOWN,
    PORT_STATUS_OPEN,
    PORT_STATUS_CLOSED,
    PORT_STATUS_FILTERED
} port_status_t;

// Port info
typedef struct {
    uint16_t port;
    port_status_t status;
    char service[32];       // Service name (if known)
} port_info_t;

// Host scan result
typedef struct {
    uint32_t ip;            // IP address (network byte order)
    char ip_str[16];        // IP as string
    uint8_t mac[6];         // MAC address (for ARP scan)
    char mac_str[18];       // MAC as string
    host_status_t status;
    uint32_t rtt_us;        // Round-trip time in microseconds

    // Port scan results
    port_info_t *ports;
    int port_count;

    // Timestamps
    uint64_t discovered_at;
} scan_result_t;

// Scan progress callback
typedef void (*scan_progress_cb)(int current, int total, void *user_data);

// Scan result callback (called for each discovered host)
typedef void (*scan_result_cb)(const scan_result_t *result, void *user_data);

// Scan configuration
typedef struct {
    scan_type_t type;
    const char *iface;          // Network interface to use
    const char *target;         // Target range (CIDR notation: 192.168.1.0/24)

    // Port scan options
    uint16_t *ports;            // Array of ports to scan (NULL for default)
    int port_count;             // Number of ports

    // Timing options
    int timeout_ms;             // Timeout per host (default: 1000)
    int rate_limit;             // Max packets per second (0 = no limit)
    int retries;                // Number of retries (default: 2)

    // Callbacks
    scan_progress_cb on_progress;
    scan_result_cb on_result;
    void *user_data;
} scan_config_t;

// Scanner handle
typedef struct scanner scanner_t;

// Create/destroy scanner
scanner_t* scanner_create(const scan_config_t *config);
void scanner_destroy(scanner_t *scanner);

// Start/stop scanning
int scanner_start(scanner_t *scanner);
void scanner_stop(scanner_t *scanner);
bool scanner_is_running(scanner_t *scanner);

// Get scan progress
int scanner_get_progress(scanner_t *scanner, int *current, int *total);

// Get results
int scanner_get_results(scanner_t *scanner, scan_result_t **results);
void scanner_free_results(scan_result_t *results, int count);

// Utility functions
int parse_cidr(const char *cidr, uint32_t *network, uint32_t *mask);
int ip_range_count(uint32_t network, uint32_t mask);
void ip_to_str(uint32_t ip, char *buf, size_t len);
uint32_t str_to_ip(const char *str);
void mac_to_str(const uint8_t *mac, char *buf, size_t len);

// Well-known ports for quick scan
extern const uint16_t COMMON_PORTS[];
extern const int COMMON_PORTS_COUNT;

// Service name lookup
const char* get_service_name(uint16_t port);

#endif // SCANNER_H

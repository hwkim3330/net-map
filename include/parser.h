/**
 * net-map - Protocol parser
 */

#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stdbool.h>

// Protocol types
typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ETHERNET,
    PROTO_ARP,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_DNS,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DHCP,
} protocol_t;

// Ethernet header
typedef struct {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ethertype;
} eth_header_t;

// IPv4 header
typedef struct {
    uint8_t version;
    uint8_t ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} ipv4_header_t;

// TCP header
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} tcp_header_t;

// UDP header
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

// Parsed packet info
typedef struct {
    // Layer 2
    eth_header_t eth;

    // Layer 3
    bool has_ip;
    ipv4_header_t ip;

    // Layer 4
    bool has_tcp;
    bool has_udp;
    tcp_header_t tcp;
    udp_header_t udp;

    // Payload
    const uint8_t *payload;
    uint32_t payload_len;

    // Protocol detection
    protocol_t top_protocol;

    // String representations (for display)
    char src_mac_str[32];
    char dst_mac_str[32];
    char src_ip_str[64];
    char dst_ip_str[64];
    char protocol_str[32];
    char info[256];
} parsed_packet_t;

// Parser functions
int parse_packet(const uint8_t *data, uint32_t len, parsed_packet_t *result);

// Utility functions
void mac_to_string(const uint8_t *mac, char *str);
void ip_to_string(uint32_t ip, char *str);
const char* protocol_to_string(protocol_t proto);

#endif // PARSER_H

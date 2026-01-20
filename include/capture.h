/**
 * net-map - Packet capture module
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include "platform.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_PACKET_SIZE 65535

// Packet structure
typedef struct {
    uint64_t timestamp_us;      // Microseconds since epoch
    uint32_t caplen;            // Captured length
    uint32_t origlen;           // Original length
    uint8_t data[MAX_PACKET_SIZE];
} packet_t;

// Capture statistics
typedef struct {
    uint64_t packets_received;
    uint64_t packets_dropped;
    uint64_t bytes_received;
} capture_stats_t;

// Callback for received packets
typedef void (*packet_callback_t)(const packet_t *pkt, void *user_data);

// Capture handle (opaque)
typedef struct capture_handle capture_handle_t;

// Capture functions
capture_handle_t* capture_open(const char *device, int snaplen, int promisc, int timeout_ms, char *errbuf);
void capture_close(capture_handle_t *handle);

int capture_set_filter(capture_handle_t *handle, const char *filter, char *errbuf);

int capture_start(capture_handle_t *handle, packet_callback_t callback, void *user_data);
void capture_stop(capture_handle_t *handle);
bool capture_is_running(capture_handle_t *handle);

int capture_get_stats(capture_handle_t *handle, capture_stats_t *stats);

// Single packet capture (blocking)
int capture_next(capture_handle_t *handle, packet_t *pkt);

// Save to pcap file
int capture_save_pcap(const char *filename, const packet_t *packets, int count);

#endif // CAPTURE_H

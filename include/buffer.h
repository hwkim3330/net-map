/**
 * net-map - Ring buffer for packet storage
 */

#ifndef BUFFER_H
#define BUFFER_H

#include "capture.h"
#include "parser.h"
#include "platform.h"
#include <stdint.h>
#include <stdbool.h>

// Packet entry in buffer
typedef struct {
    uint64_t id;                // Unique packet ID
    packet_t raw;               // Raw packet data
    parsed_packet_t parsed;     // Parsed packet info
} packet_entry_t;

// Ring buffer handle
typedef struct packet_buffer packet_buffer_t;

// Buffer functions
packet_buffer_t* buffer_create(uint32_t capacity);
void buffer_destroy(packet_buffer_t *buf);

// Add packet (thread-safe)
int buffer_push(packet_buffer_t *buf, const packet_t *pkt);

// Get packets (thread-safe)
int buffer_get_range(packet_buffer_t *buf, uint64_t start_id, uint32_t count, packet_entry_t **entries);
void buffer_free_entries(packet_entry_t *entries);

// Get packet by ID
packet_entry_t* buffer_get(packet_buffer_t *buf, uint64_t id);

// Buffer stats
uint32_t buffer_count(packet_buffer_t *buf);
uint64_t buffer_newest_id(packet_buffer_t *buf);
uint64_t buffer_oldest_id(packet_buffer_t *buf);

// Clear buffer
void buffer_clear(packet_buffer_t *buf);

#endif // BUFFER_H

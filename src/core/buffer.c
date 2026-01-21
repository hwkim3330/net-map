/**
 * net-map - Ring buffer implementation
 */

#include "buffer.h"
#include <stdlib.h>
#include <string.h>

struct packet_buffer {
    packet_entry_t *entries;
    uint32_t capacity;
    uint32_t head;
    uint32_t count;
    uint64_t next_id;
    mutex_t mutex;
};

packet_buffer_t* buffer_create(uint32_t capacity) {
    packet_buffer_t *buf = calloc(1, sizeof(packet_buffer_t));
    if (!buf) return NULL;

    buf->entries = calloc(capacity, sizeof(packet_entry_t));
    if (!buf->entries) {
        free(buf);
        return NULL;
    }

    buf->capacity = capacity;
    buf->head = 0;
    buf->count = 0;
    buf->next_id = 1;
    mutex_init(&buf->mutex);

    return buf;
}

void buffer_destroy(packet_buffer_t *buf) {
    if (!buf) return;

    mutex_destroy(&buf->mutex);
    free(buf->entries);
    free(buf);
}

int buffer_push(packet_buffer_t *buf, const packet_t *pkt) {
    if (!buf || !pkt) return -1;

    mutex_lock(&buf->mutex);

    // Find insertion index
    uint32_t idx = (buf->head + buf->count) % buf->capacity;

    // Copy packet data
    packet_entry_t *entry = &buf->entries[idx];
    entry->id = buf->next_id++;
    memcpy(&entry->raw, pkt, sizeof(packet_t));

    // Parse packet
    parse_packet(pkt->data, pkt->caplen, &entry->parsed);

    // Update count
    if (buf->count < buf->capacity) {
        buf->count++;
    } else {
        // Buffer full, move head
        buf->head = (buf->head + 1) % buf->capacity;
    }

    mutex_unlock(&buf->mutex);

    return 0;
}

int buffer_get_range(packet_buffer_t *buf, uint64_t start_id, uint32_t count, packet_entry_t **entries) {
    if (!buf || !entries) return -1;

    mutex_lock(&buf->mutex);

    if (buf->count == 0) {
        mutex_unlock(&buf->mutex);
        *entries = NULL;
        return 0;
    }

    // Find starting point
    uint64_t oldest_id = buf->entries[buf->head].id;
    uint64_t newest_id = buf->entries[(buf->head + buf->count - 1) % buf->capacity].id;

    // If start_id is 0 or less than oldest, start from oldest
    if (start_id == 0 || start_id < oldest_id) start_id = oldest_id;

    // If start_id is beyond newest, return packets newer than start_id
    if (start_id > newest_id) {
        mutex_unlock(&buf->mutex);
        *entries = NULL;
        return 0;
    }

    // Calculate offset
    uint32_t offset = (uint32_t)(start_id - oldest_id);
    uint32_t available = buf->count - offset;
    uint32_t to_copy = (count < available) ? count : available;

    // Allocate result
    *entries = calloc(to_copy, sizeof(packet_entry_t));
    if (!*entries) {
        mutex_unlock(&buf->mutex);
        return -1;
    }

    // Copy entries
    for (uint32_t i = 0; i < to_copy; i++) {
        uint32_t idx = (buf->head + offset + i) % buf->capacity;
        memcpy(&(*entries)[i], &buf->entries[idx], sizeof(packet_entry_t));
    }

    mutex_unlock(&buf->mutex);

    return (int)to_copy;
}

void buffer_free_entries(packet_entry_t *entries) {
    free(entries);
}

packet_entry_t* buffer_get(packet_buffer_t *buf, uint64_t id) {
    if (!buf) return NULL;

    mutex_lock(&buf->mutex);

    if (buf->count == 0) {
        mutex_unlock(&buf->mutex);
        return NULL;
    }

    uint64_t oldest_id = buf->entries[buf->head].id;
    uint64_t newest_id = buf->entries[(buf->head + buf->count - 1) % buf->capacity].id;

    if (id < oldest_id || id > newest_id) {
        mutex_unlock(&buf->mutex);
        return NULL;
    }

    uint32_t offset = (uint32_t)(id - oldest_id);
    uint32_t idx = (buf->head + offset) % buf->capacity;

    // Return pointer (caller must not free)
    packet_entry_t *entry = &buf->entries[idx];

    mutex_unlock(&buf->mutex);

    return entry;
}

uint32_t buffer_count(packet_buffer_t *buf) {
    if (!buf) return 0;

    mutex_lock(&buf->mutex);
    uint32_t count = buf->count;
    mutex_unlock(&buf->mutex);

    return count;
}

uint64_t buffer_newest_id(packet_buffer_t *buf) {
    if (!buf) return 0;

    mutex_lock(&buf->mutex);
    uint64_t id = (buf->count > 0) ? buf->next_id - 1 : 0;
    mutex_unlock(&buf->mutex);

    return id;
}

uint64_t buffer_oldest_id(packet_buffer_t *buf) {
    if (!buf) return 0;

    mutex_lock(&buf->mutex);
    uint64_t id = (buf->count > 0) ? buf->entries[buf->head].id : 0;
    mutex_unlock(&buf->mutex);

    return id;
}

void buffer_clear(packet_buffer_t *buf) {
    if (!buf) return;

    mutex_lock(&buf->mutex);
    buf->head = 0;
    buf->count = 0;
    mutex_unlock(&buf->mutex);
}

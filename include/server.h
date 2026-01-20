/**
 * net-map - Web server module
 */

#ifndef SERVER_H
#define SERVER_H

#include "buffer.h"
#include "capture.h"

// Server configuration
typedef struct {
    int port;
    const char *static_dir;
    packet_buffer_t *packet_buffer;
    capture_handle_t *capture;
} server_config_t;

// Server handle
typedef struct server server_t;

// Server functions
server_t* server_create(const server_config_t *config);
void server_destroy(server_t *srv);

int server_start(server_t *srv);
void server_stop(server_t *srv);

// Poll for events (call in main loop)
void server_poll(server_t *srv, int timeout_ms);

#endif // SERVER_H

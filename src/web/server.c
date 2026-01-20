/**
 * net-map - Web server implementation using mongoose
 */

#include "server.h"
#include "mongoose.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct server {
    struct mg_mgr mgr;
    server_config_t config;
    bool running;
};

// Forward declarations
static void handle_api_devices(struct mg_connection *c, struct mg_http_message *hm);
static void handle_api_packets(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_capture_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_capture_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_stats(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);

// CORS headers
static const char *cors_headers =
    "Access-Control-Allow-Origin: *\r\n"
    "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
    "Access-Control-Allow-Headers: Content-Type\r\n";

static void send_json(struct mg_connection *c, int status, cJSON *json) {
    char *str = cJSON_Print(json);
    mg_http_reply(c, status,
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n",
        "%s", str);
    free(str);
}

static void send_error(struct mg_connection *c, int status, const char *msg) {
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "error", msg);
    send_json(c, status, json);
    cJSON_Delete(json);
}

// Event handler
static void event_handler(struct mg_connection *c, int ev, void *ev_data) {
    server_t *srv = (server_t*)c->fn_data;

    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message*)ev_data;

        // Handle OPTIONS (CORS preflight)
        if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
            mg_http_reply(c, 204, cors_headers, "");
            return;
        }

        // API routes
        if (mg_match(hm->uri, mg_str("/api/devices"), NULL)) {
            handle_api_devices(c, hm);
        }
        else if (mg_match(hm->uri, mg_str("/api/packets"), NULL)) {
            handle_api_packets(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/capture/start"), NULL)) {
            handle_api_capture_start(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/capture/stop"), NULL)) {
            handle_api_capture_stop(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/stats"), NULL)) {
            handle_api_stats(c, hm, srv);
        }
        else {
            // Serve static files
            struct mg_http_serve_opts opts = {
                .root_dir = srv->config.static_dir,
                .ssi_pattern = "#.html"
            };
            mg_http_serve_dir(c, hm, &opts);
        }
    }
}

// API: GET /api/devices
static void handle_api_devices(struct mg_connection *c, struct mg_http_message *hm) {
    (void)hm;

    device_info_t *devices;
    int count = get_device_list(&devices);

    if (count < 0) {
        send_error(c, 500, "Failed to get device list");
        return;
    }

    cJSON *json = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *dev = cJSON_CreateObject();
        cJSON_AddStringToObject(dev, "name", devices[i].name);
        cJSON_AddStringToObject(dev, "description", devices[i].description);
        cJSON_AddStringToObject(dev, "ip", devices[i].ip_addr);
        cJSON_AddBoolToObject(dev, "up", devices[i].is_up);
        cJSON_AddBoolToObject(dev, "loopback", devices[i].is_loopback);
        cJSON_AddItemToArray(json, dev);
    }

    free_device_list(devices, count);
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: GET /api/packets?from=ID&limit=N
static void handle_api_packets(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    if (!srv->config.packet_buffer) {
        send_error(c, 500, "Buffer not initialized");
        return;
    }

    // Parse query parameters
    char from_str[32] = "0";
    char limit_str[32] = "100";
    mg_http_get_var(&hm->query, "from", from_str, sizeof(from_str));
    mg_http_get_var(&hm->query, "limit", limit_str, sizeof(limit_str));

    uint64_t from_id = strtoull(from_str, NULL, 10);
    uint32_t limit = (uint32_t)atoi(limit_str);
    if (limit > 1000) limit = 1000;

    packet_entry_t *entries;
    int count = buffer_get_range(srv->config.packet_buffer, from_id, limit, &entries);

    if (count < 0) {
        send_error(c, 500, "Failed to get packets");
        return;
    }

    cJSON *json = cJSON_CreateObject();
    cJSON *packets = cJSON_CreateArray();

    for (int i = 0; i < count; i++) {
        cJSON *pkt = cJSON_CreateObject();
        cJSON_AddNumberToObject(pkt, "id", (double)entries[i].id);
        cJSON_AddNumberToObject(pkt, "timestamp", (double)entries[i].raw.timestamp_us);
        cJSON_AddNumberToObject(pkt, "length", entries[i].raw.caplen);
        cJSON_AddStringToObject(pkt, "src", entries[i].parsed.src_ip_str);
        cJSON_AddStringToObject(pkt, "dst", entries[i].parsed.dst_ip_str);
        cJSON_AddStringToObject(pkt, "protocol", entries[i].parsed.protocol_str);
        cJSON_AddStringToObject(pkt, "info", entries[i].parsed.info);
        cJSON_AddItemToArray(packets, pkt);
    }

    cJSON_AddItemToObject(json, "packets", packets);
    cJSON_AddNumberToObject(json, "total", buffer_count(srv->config.packet_buffer));
    cJSON_AddNumberToObject(json, "newest_id", (double)buffer_newest_id(srv->config.packet_buffer));

    buffer_free_entries(entries);
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/capture/start
static void handle_api_capture_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    if (srv->config.capture && capture_is_running(srv->config.capture)) {
        send_error(c, 400, "Capture already running");
        return;
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "message", "Capture started");
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/capture/stop
static void handle_api_capture_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    if (srv->config.capture) {
        capture_stop(srv->config.capture);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "message", "Capture stopped");
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: GET /api/stats
static void handle_api_stats(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    cJSON *json = cJSON_CreateObject();

    if (srv->config.capture) {
        capture_stats_t stats;
        if (capture_get_stats(srv->config.capture, &stats) == 0) {
            cJSON_AddNumberToObject(json, "packets_received", (double)stats.packets_received);
            cJSON_AddNumberToObject(json, "packets_dropped", (double)stats.packets_dropped);
            cJSON_AddNumberToObject(json, "bytes_received", (double)stats.bytes_received);
        }
        cJSON_AddBoolToObject(json, "capturing", capture_is_running(srv->config.capture));
    } else {
        cJSON_AddBoolToObject(json, "capturing", false);
    }

    if (srv->config.packet_buffer) {
        cJSON_AddNumberToObject(json, "buffer_count", buffer_count(srv->config.packet_buffer));
    }

    send_json(c, 200, json);
    cJSON_Delete(json);
}

server_t* server_create(const server_config_t *config) {
    server_t *srv = calloc(1, sizeof(server_t));
    if (!srv) return NULL;

    memcpy(&srv->config, config, sizeof(server_config_t));
    mg_mgr_init(&srv->mgr);

    return srv;
}

void server_destroy(server_t *srv) {
    if (!srv) return;

    mg_mgr_free(&srv->mgr);
    free(srv);
}

int server_start(server_t *srv) {
    char addr[64];
    snprintf(addr, sizeof(addr), "http://0.0.0.0:%d", srv->config.port);

    struct mg_connection *c = mg_http_listen(&srv->mgr, addr, event_handler, srv);
    if (!c) {
        return -1;
    }

    srv->running = true;
    printf("Server started at %s\n", addr);
    printf("Static files: %s\n", srv->config.static_dir);

    return 0;
}

void server_stop(server_t *srv) {
    if (!srv) return;
    srv->running = false;
}

void server_poll(server_t *srv, int timeout_ms) {
    if (!srv) return;
    mg_mgr_poll(&srv->mgr, timeout_ms);
}

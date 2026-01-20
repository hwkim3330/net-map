/**
 * net-map - Web server implementation using mongoose
 */

#include "server.h"
#include "mongoose.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Packet callback for capture
static void packet_callback(const packet_t *pkt, void *user_data);

struct server {
    struct mg_mgr mgr;
    server_config_t config;
    bool running;

    // Dynamic capture management
    capture_handle_t *capture;
    char current_device[256];
    char current_filter[256];
};

// Forward declarations
static void handle_api_devices(struct mg_connection *c, struct mg_http_message *hm);
static void handle_api_packets(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_capture_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_capture_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_stats(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_clear(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);

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

// Packet callback
static void packet_callback(const packet_t *pkt, void *user_data) {
    server_t *srv = (server_t*)user_data;
    if (srv && srv->config.packet_buffer) {
        buffer_push(srv->config.packet_buffer, pkt);
    }
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
        else if (mg_match(hm->uri, mg_str("/api/clear"), NULL)) {
            handle_api_clear(c, hm, srv);
        }
        else {
            // Serve static files
            struct mg_http_serve_opts opts = {
                .root_dir = srv->config.static_dir
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
        parsed_packet_t *p = &entries[i].parsed;

        // Basic info
        cJSON_AddNumberToObject(pkt, "id", (double)entries[i].id);
        cJSON_AddNumberToObject(pkt, "timestamp", (double)entries[i].raw.timestamp_us);
        cJSON_AddNumberToObject(pkt, "length", entries[i].raw.caplen);
        cJSON_AddStringToObject(pkt, "src", p->src_ip_str);
        cJSON_AddStringToObject(pkt, "dst", p->dst_ip_str);
        cJSON_AddStringToObject(pkt, "protocol", p->protocol_str);
        cJSON_AddStringToObject(pkt, "info", p->info);

        // Ethernet layer
        cJSON *eth = cJSON_CreateObject();
        cJSON_AddStringToObject(eth, "src_mac", p->src_mac_str);
        cJSON_AddStringToObject(eth, "dst_mac", p->dst_mac_str);
        cJSON_AddNumberToObject(eth, "ethertype", p->eth.ethertype);
        cJSON_AddItemToObject(pkt, "ethernet", eth);

        // IP layer (if present)
        if (p->has_ip) {
            cJSON *ip = cJSON_CreateObject();
            cJSON_AddNumberToObject(ip, "version", p->ip.version);
            cJSON_AddNumberToObject(ip, "ihl", p->ip.ihl);
            cJSON_AddNumberToObject(ip, "tos", p->ip.tos);
            cJSON_AddNumberToObject(ip, "total_len", p->ip.total_len);
            cJSON_AddNumberToObject(ip, "id", p->ip.id);
            cJSON_AddNumberToObject(ip, "flags", (p->ip.flags_offset >> 13) & 0x07);
            cJSON_AddNumberToObject(ip, "frag_offset", p->ip.flags_offset & 0x1FFF);
            cJSON_AddNumberToObject(ip, "ttl", p->ip.ttl);
            cJSON_AddNumberToObject(ip, "protocol", p->ip.protocol);
            cJSON_AddNumberToObject(ip, "checksum", p->ip.checksum);
            cJSON_AddStringToObject(ip, "src", p->src_ip_str);
            cJSON_AddStringToObject(ip, "dst", p->dst_ip_str);
            cJSON_AddItemToObject(pkt, "ip", ip);
        }

        // TCP layer (if present)
        if (p->has_tcp) {
            cJSON *tcp = cJSON_CreateObject();
            cJSON_AddNumberToObject(tcp, "src_port", p->tcp.src_port);
            cJSON_AddNumberToObject(tcp, "dst_port", p->tcp.dst_port);
            cJSON_AddNumberToObject(tcp, "seq", (double)p->tcp.seq);
            cJSON_AddNumberToObject(tcp, "ack", (double)p->tcp.ack);
            cJSON_AddNumberToObject(tcp, "data_offset", p->tcp.data_offset);
            cJSON_AddNumberToObject(tcp, "flags", p->tcp.flags);
            cJSON_AddBoolToObject(tcp, "syn", (p->tcp.flags & 0x02) != 0);
            cJSON_AddBoolToObject(tcp, "ack_flag", (p->tcp.flags & 0x10) != 0);
            cJSON_AddBoolToObject(tcp, "fin", (p->tcp.flags & 0x01) != 0);
            cJSON_AddBoolToObject(tcp, "rst", (p->tcp.flags & 0x04) != 0);
            cJSON_AddBoolToObject(tcp, "psh", (p->tcp.flags & 0x08) != 0);
            cJSON_AddNumberToObject(tcp, "window", p->tcp.window);
            cJSON_AddNumberToObject(tcp, "checksum", p->tcp.checksum);
            cJSON_AddNumberToObject(tcp, "urgent", p->tcp.urgent);
            cJSON_AddNumberToObject(tcp, "payload_len", p->payload_len);
            cJSON_AddItemToObject(pkt, "tcp", tcp);
        }

        // UDP layer (if present)
        if (p->has_udp) {
            cJSON *udp = cJSON_CreateObject();
            cJSON_AddNumberToObject(udp, "src_port", p->udp.src_port);
            cJSON_AddNumberToObject(udp, "dst_port", p->udp.dst_port);
            cJSON_AddNumberToObject(udp, "length", p->udp.length);
            cJSON_AddNumberToObject(udp, "checksum", p->udp.checksum);
            cJSON_AddNumberToObject(udp, "payload_len", p->payload_len);
            cJSON_AddItemToObject(pkt, "udp", udp);
        }

        cJSON_AddItemToArray(packets, pkt);
    }

    cJSON_AddItemToObject(json, "packets", packets);
    cJSON_AddNumberToObject(json, "total", buffer_count(srv->config.packet_buffer));
    cJSON_AddNumberToObject(json, "newest_id", (double)buffer_newest_id(srv->config.packet_buffer));

    buffer_free_entries(entries);
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/capture/start  body: {"device": "...", "filter": "..."}
static void handle_api_capture_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    // Check if already capturing
    if (srv->capture && capture_is_running(srv->capture)) {
        send_error(c, 400, "Capture already running. Stop it first.");
        return;
    }

    // Parse JSON body
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) {
        send_error(c, 400, "Invalid JSON body");
        return;
    }

    cJSON *device_json = cJSON_GetObjectItem(body, "device");
    cJSON *filter_json = cJSON_GetObjectItem(body, "filter");

    if (!device_json || !cJSON_IsString(device_json)) {
        cJSON_Delete(body);
        send_error(c, 400, "Missing 'device' field");
        return;
    }

    const char *device = device_json->valuestring;
    const char *filter = (filter_json && cJSON_IsString(filter_json)) ? filter_json->valuestring : NULL;

    // Close existing capture if any
    if (srv->capture) {
        capture_stop(srv->capture);
        capture_close(srv->capture);
        srv->capture = NULL;
    }

    // Open new capture
    char errbuf[256];
    srv->capture = capture_open(device, 65535, 1, 1000, errbuf);
    if (!srv->capture) {
        cJSON_Delete(body);
        send_error(c, 500, errbuf);
        return;
    }

    // Set filter if provided
    if (filter && filter[0]) {
        if (capture_set_filter(srv->capture, filter, errbuf) != 0) {
            printf("Warning: Failed to set filter: %s\n", errbuf);
        }
        strncpy(srv->current_filter, filter, sizeof(srv->current_filter) - 1);
    } else {
        srv->current_filter[0] = '\0';
    }

    // Start capture
    if (capture_start(srv->capture, packet_callback, srv) != 0) {
        capture_close(srv->capture);
        srv->capture = NULL;
        cJSON_Delete(body);
        send_error(c, 500, "Failed to start capture");
        return;
    }

    strncpy(srv->current_device, device, sizeof(srv->current_device) - 1);
    printf("Capture started on: %s\n", device);

    cJSON_Delete(body);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "device", device);
    cJSON_AddStringToObject(json, "message", "Capture started");
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/capture/stop
static void handle_api_capture_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    if (srv->capture) {
        capture_stop(srv->capture);
        capture_close(srv->capture);
        srv->capture = NULL;
        srv->current_device[0] = '\0';
        printf("Capture stopped\n");
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

    bool is_capturing = srv->capture && capture_is_running(srv->capture);
    cJSON_AddBoolToObject(json, "capturing", is_capturing);

    if (srv->capture) {
        capture_stats_t stats;
        if (capture_get_stats(srv->capture, &stats) == 0) {
            cJSON_AddNumberToObject(json, "packets_received", (double)stats.packets_received);
            cJSON_AddNumberToObject(json, "packets_dropped", (double)stats.packets_dropped);
            cJSON_AddNumberToObject(json, "bytes_received", (double)stats.bytes_received);
        }
        cJSON_AddStringToObject(json, "device", srv->current_device);
    }

    if (srv->config.packet_buffer) {
        cJSON_AddNumberToObject(json, "buffer_count", buffer_count(srv->config.packet_buffer));
    }

    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/clear
static void handle_api_clear(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    if (srv->config.packet_buffer) {
        buffer_clear(srv->config.packet_buffer);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "message", "Buffer cleared");
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

    // Stop capture if running
    if (srv->capture) {
        capture_stop(srv->capture);
        capture_close(srv->capture);
    }

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

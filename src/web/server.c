/**
 * net-map - Web server implementation using mongoose
 */

#include "server.h"
#include "scanner.h"
#include "mongoose.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

    // Network scanner
    scanner_t *scanner;
};

// Forward declarations
static void handle_api_devices(struct mg_connection *c, struct mg_http_message *hm);
static void handle_api_packets(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_capture_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_capture_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_stats(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_clear(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_save_pcap(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_scan_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_scan_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_scan_status(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_scan_results(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_pcap_load(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);
static void handle_api_packet_inject(struct mg_connection *c, struct mg_http_message *hm, server_t *srv);

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
        else if (mg_match(hm->uri, mg_str("/api/save"), NULL)) {
            handle_api_save_pcap(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/scan/start"), NULL)) {
            handle_api_scan_start(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/scan/stop"), NULL)) {
            handle_api_scan_stop(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/scan/status"), NULL)) {
            handle_api_scan_status(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/scan/results"), NULL)) {
            handle_api_scan_results(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/pcap/load"), NULL)) {
            handle_api_pcap_load(c, hm, srv);
        }
        else if (mg_match(hm->uri, mg_str("/api/packet/inject"), NULL)) {
            handle_api_packet_inject(c, hm, srv);
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

    cJSON *json = cJSON_CreateObject();
    cJSON *devArray = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *dev = cJSON_CreateObject();
        cJSON_AddStringToObject(dev, "name", devices[i].name);
        cJSON_AddStringToObject(dev, "description", devices[i].description);
        cJSON_AddStringToObject(dev, "ip", devices[i].ip_addr);
        cJSON_AddBoolToObject(dev, "up", devices[i].is_up);
        cJSON_AddBoolToObject(dev, "loopback", devices[i].is_loopback);
        cJSON_AddItemToArray(devArray, dev);
    }
    cJSON_AddItemToObject(json, "devices", devArray);

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
    cJSON_AddBoolToObject(json, "success", true);

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
        cJSON_AddStringToObject(json, "filter", srv->current_filter);
    }

    if (srv->config.packet_buffer) {
        cJSON_AddNumberToObject(json, "buffer_count", buffer_count(srv->config.packet_buffer));
        cJSON_AddNumberToObject(json, "newest_id", (double)buffer_newest_id(srv->config.packet_buffer));
        cJSON_AddNumberToObject(json, "oldest_id", (double)buffer_oldest_id(srv->config.packet_buffer));
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

// API: GET /api/save - Save packets to PCAP format and return as download
static void handle_api_save_pcap(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    if (!srv->config.packet_buffer) {
        send_error(c, 500, "Buffer not initialized");
        return;
    }

    uint32_t count = buffer_count(srv->config.packet_buffer);
    if (count == 0) {
        send_error(c, 400, "No packets to save");
        return;
    }

    // Get all packets from buffer
    uint64_t oldest = buffer_oldest_id(srv->config.packet_buffer);
    packet_entry_t *entries;
    int num_packets = buffer_get_range(srv->config.packet_buffer, oldest, count, &entries);

    if (num_packets <= 0 || !entries) {
        send_error(c, 500, "Failed to get packets");
        return;
    }

    // Calculate PCAP file size
    // PCAP global header: 24 bytes
    // Each packet: 16 bytes header + packet data
    size_t pcap_size = 24;
    for (int i = 0; i < num_packets; i++) {
        pcap_size += 16 + entries[i].raw.caplen;
    }

    // Allocate buffer for PCAP data
    uint8_t *pcap_data = malloc(pcap_size);
    if (!pcap_data) {
        buffer_free_entries(entries);
        send_error(c, 500, "Out of memory");
        return;
    }

    uint8_t *ptr = pcap_data;

    // Write PCAP global header
    // Magic number (microseconds)
    uint32_t magic = 0xa1b2c3d4;
    memcpy(ptr, &magic, 4); ptr += 4;
    // Version major
    uint16_t ver_major = 2;
    memcpy(ptr, &ver_major, 2); ptr += 2;
    // Version minor
    uint16_t ver_minor = 4;
    memcpy(ptr, &ver_minor, 2); ptr += 2;
    // Timezone offset (0)
    uint32_t thiszone = 0;
    memcpy(ptr, &thiszone, 4); ptr += 4;
    // Timestamp accuracy (0)
    uint32_t sigfigs = 0;
    memcpy(ptr, &sigfigs, 4); ptr += 4;
    // Snaplen
    uint32_t snaplen = 65535;
    memcpy(ptr, &snaplen, 4); ptr += 4;
    // Network type (Ethernet)
    uint32_t network = 1;
    memcpy(ptr, &network, 4); ptr += 4;

    // Write each packet
    for (int i = 0; i < num_packets; i++) {
        packet_t *pkt = &entries[i].raw;

        // Timestamp seconds
        uint32_t ts_sec = (uint32_t)(pkt->timestamp_us / 1000000);
        memcpy(ptr, &ts_sec, 4); ptr += 4;
        // Timestamp microseconds
        uint32_t ts_usec = (uint32_t)(pkt->timestamp_us % 1000000);
        memcpy(ptr, &ts_usec, 4); ptr += 4;
        // Captured length
        uint32_t caplen = pkt->caplen;
        memcpy(ptr, &caplen, 4); ptr += 4;
        // Original length
        uint32_t origlen = pkt->origlen;
        memcpy(ptr, &origlen, 4); ptr += 4;
        // Packet data
        memcpy(ptr, pkt->data, pkt->caplen);
        ptr += pkt->caplen;
    }

    buffer_free_entries(entries);

    // Generate filename with timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char filename[64];
    strftime(filename, sizeof(filename), "capture_%Y%m%d_%H%M%S.pcap", tm_info);

    // Send response with PCAP file
    char headers[256];
    snprintf(headers, sizeof(headers),
        "Content-Type: application/vnd.tcpdump.pcap\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Access-Control-Allow-Origin: *\r\n",
        filename);

    mg_http_reply(c, 200, headers, "");
    mg_send(c, pcap_data, pcap_size);

    free(pcap_data);
}

// API: POST /api/scan/start - Start network scan
static void handle_api_scan_start(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    // Parse JSON body
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) {
        send_error(c, 400, "Invalid JSON");
        return;
    }

    // Stop existing scan if running
    if (srv->scanner && scanner_is_running(srv->scanner)) {
        scanner_stop(srv->scanner);
        scanner_destroy(srv->scanner);
        srv->scanner = NULL;
    }

    // Get parameters
    cJSON *target_json = cJSON_GetObjectItem(body, "target");
    cJSON *type_json = cJSON_GetObjectItem(body, "type");
    cJSON *interface_json = cJSON_GetObjectItem(body, "interface");
    cJSON *ports_json = cJSON_GetObjectItem(body, "ports");
    cJSON *timeout_json = cJSON_GetObjectItem(body, "timeout");

    if (!target_json || !cJSON_IsString(target_json)) {
        cJSON_Delete(body);
        send_error(c, 400, "Missing target parameter");
        return;
    }

    // Build scan config
    scan_config_t config = {0};
    config.target = target_json->valuestring;
    config.timeout_ms = timeout_json ? timeout_json->valueint : 1000;
    config.rate_limit = 100;  // 100 packets/sec default

    // Determine scan type
    if (type_json && cJSON_IsString(type_json)) {
        const char *type_str = type_json->valuestring;
        if (strcmp(type_str, "arp") == 0) {
            config.type = SCAN_TYPE_ARP;
        } else if (strcmp(type_str, "ping") == 0) {
            config.type = SCAN_TYPE_PING;
        } else if (strcmp(type_str, "syn") == 0 || strcmp(type_str, "port") == 0) {
            config.type = SCAN_TYPE_SYN;
        } else {
            config.type = SCAN_TYPE_PING;  // Default
        }
    } else {
        config.type = SCAN_TYPE_PING;
    }

    // Parse ports if specified
    uint16_t *custom_ports = NULL;
    int custom_port_count = 0;
    if (ports_json && cJSON_IsString(ports_json)) {
        const char *ports_str = ports_json->valuestring;
        // Parse comma-separated ports
        char *ports_copy = strdup(ports_str);
        char *token = strtok(ports_copy, ",");
        while (token) {
            custom_port_count++;
            token = strtok(NULL, ",");
        }
        if (custom_port_count > 0) {
            custom_ports = malloc(custom_port_count * sizeof(uint16_t));
            strcpy(ports_copy, ports_str);
            token = strtok(ports_copy, ",");
            int i = 0;
            while (token && i < custom_port_count) {
                custom_ports[i++] = (uint16_t)atoi(token);
                token = strtok(NULL, ",");
            }
            config.ports = custom_ports;
            config.port_count = custom_port_count;
        }
        free(ports_copy);
    }

    if (interface_json && cJSON_IsString(interface_json)) {
        config.iface = interface_json->valuestring;
    } else {
        config.iface = srv->current_device;
    }

    // Create and start scanner
    srv->scanner = scanner_create(&config);
    if (!srv->scanner) {
        if (custom_ports) free(custom_ports);
        cJSON_Delete(body);
        send_error(c, 500, "Failed to create scanner");
        return;
    }

    if (scanner_start(srv->scanner) != 0) {
        scanner_destroy(srv->scanner);
        srv->scanner = NULL;
        if (custom_ports) free(custom_ports);
        cJSON_Delete(body);
        send_error(c, 500, "Failed to start scan");
        return;
    }

    if (custom_ports) free(custom_ports);
    cJSON_Delete(body);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "message", "Scan started");
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/scan/stop - Stop network scan
static void handle_api_scan_stop(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    if (srv->scanner) {
        scanner_stop(srv->scanner);
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddStringToObject(json, "message", "Scan stopped");
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: GET /api/scan/status - Get scan status
static void handle_api_scan_status(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);

    if (srv->scanner) {
        cJSON_AddBoolToObject(json, "running", scanner_is_running(srv->scanner));

        int current, total;
        scanner_get_progress(srv->scanner, &current, &total);
        cJSON_AddNumberToObject(json, "current", current);
        cJSON_AddNumberToObject(json, "total", total);

        if (total > 0) {
            cJSON_AddNumberToObject(json, "progress", (double)current / total * 100.0);
        }
    } else {
        cJSON_AddBoolToObject(json, "running", false);
        cJSON_AddNumberToObject(json, "current", 0);
        cJSON_AddNumberToObject(json, "total", 0);
    }

    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: GET /api/scan/results - Get scan results
static void handle_api_scan_results(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    (void)hm;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);

    cJSON *hosts = cJSON_CreateArray();

    if (srv->scanner) {
        scan_result_t *results;
        int count = scanner_get_results(srv->scanner, &results);

        for (int i = 0; i < count; i++) {
            cJSON *host = cJSON_CreateObject();
            cJSON_AddStringToObject(host, "ip", results[i].ip_str);

            if (results[i].mac_str[0] != '\0') {
                cJSON_AddStringToObject(host, "mac", results[i].mac_str);
            }

            cJSON_AddStringToObject(host, "status",
                results[i].status == HOST_STATUS_UP ? "up" :
                results[i].status == HOST_STATUS_DOWN ? "down" : "unknown");

            cJSON_AddNumberToObject(host, "rtt_ms", results[i].rtt_us / 1000.0);

            // Add ports if available
            if (results[i].port_count > 0) {
                cJSON *ports = cJSON_CreateArray();
                for (int p = 0; p < results[i].port_count; p++) {
                    cJSON *port = cJSON_CreateObject();
                    cJSON_AddNumberToObject(port, "port", results[i].ports[p].port);
                    cJSON_AddStringToObject(port, "status",
                        results[i].ports[p].status == PORT_STATUS_OPEN ? "open" :
                        results[i].ports[p].status == PORT_STATUS_CLOSED ? "closed" : "filtered");
                    if (results[i].ports[p].service[0] != '\0') {
                        cJSON_AddStringToObject(port, "service", results[i].ports[p].service);
                    }
                    cJSON_AddItemToArray(ports, port);
                }
                cJSON_AddItemToObject(host, "ports", ports);
            }

            cJSON_AddItemToArray(hosts, host);
        }

        if (results) {
            scanner_free_results(results, count);
        }

        cJSON_AddNumberToObject(json, "count", count);
        cJSON_AddBoolToObject(json, "scanning", scanner_is_running(srv->scanner));
    } else {
        cJSON_AddNumberToObject(json, "count", 0);
        cJSON_AddBoolToObject(json, "scanning", false);
    }

    cJSON_AddItemToObject(json, "hosts", hosts);

    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/pcap/load - Load PCAP file into buffer
static void handle_api_pcap_load(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    if (!srv->config.packet_buffer) {
        send_error(c, 500, "Buffer not initialized");
        return;
    }

    // Check content type for multipart/form-data
    struct mg_str content_type = mg_http_get_header(hm, "Content-Type");
    if (!content_type.buf || !mg_strstr(content_type, mg_str("multipart/form-data"))) {
        send_error(c, 400, "Expected multipart/form-data");
        return;
    }

    // Extract file from multipart body
    struct mg_http_part part;
    size_t ofs = 0;
    uint8_t *pcap_data = NULL;
    size_t pcap_size = 0;

    while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
        if (mg_strcmp(part.name, mg_str("file")) == 0) {
            pcap_data = (uint8_t*)part.body.buf;
            pcap_size = part.body.len;
            break;
        }
    }

    if (!pcap_data || pcap_size < 24) {
        send_error(c, 400, "No valid PCAP file uploaded");
        return;
    }

    // Parse PCAP file header
    uint32_t magic;
    memcpy(&magic, pcap_data, 4);

    bool swap_bytes = false;
    bool nanosec = false;

    if (magic == 0xa1b2c3d4) {
        // Standard PCAP, microseconds
    } else if (magic == 0xd4c3b2a1) {
        // Swapped byte order
        swap_bytes = true;
    } else if (magic == 0xa1b23c4d) {
        // Nanosecond resolution
        nanosec = true;
    } else if (magic == 0x4d3cb2a1) {
        // Swapped nanosecond
        swap_bytes = true;
        nanosec = true;
    } else {
        send_error(c, 400, "Invalid PCAP file format");
        return;
    }

    // Clear existing buffer
    buffer_clear(srv->config.packet_buffer);

    // Skip global header (24 bytes)
    size_t offset = 24;
    int packet_count = 0;

    while (offset + 16 <= pcap_size) {
        // Read packet header
        uint32_t ts_sec, ts_usec, caplen, origlen;
        memcpy(&ts_sec, pcap_data + offset, 4);
        memcpy(&ts_usec, pcap_data + offset + 4, 4);
        memcpy(&caplen, pcap_data + offset + 8, 4);
        memcpy(&origlen, pcap_data + offset + 12, 4);

        if (swap_bytes) {
            ts_sec = ((ts_sec >> 24) & 0xff) | ((ts_sec >> 8) & 0xff00) |
                     ((ts_sec << 8) & 0xff0000) | ((ts_sec << 24) & 0xff000000);
            ts_usec = ((ts_usec >> 24) & 0xff) | ((ts_usec >> 8) & 0xff00) |
                      ((ts_usec << 8) & 0xff0000) | ((ts_usec << 24) & 0xff000000);
            caplen = ((caplen >> 24) & 0xff) | ((caplen >> 8) & 0xff00) |
                     ((caplen << 8) & 0xff0000) | ((caplen << 24) & 0xff000000);
            origlen = ((origlen >> 24) & 0xff) | ((origlen >> 8) & 0xff00) |
                      ((origlen << 8) & 0xff0000) | ((origlen << 24) & 0xff000000);
        }

        offset += 16;

        // Validate packet data
        if (offset + caplen > pcap_size || caplen > 65535) {
            break;
        }

        // Create packet and add to buffer
        packet_t pkt;
        pkt.timestamp_us = (uint64_t)ts_sec * 1000000 + (nanosec ? ts_usec / 1000 : ts_usec);
        pkt.caplen = caplen;
        pkt.origlen = origlen;
        pkt.data = pcap_data + offset;

        buffer_push(srv->config.packet_buffer, &pkt);
        packet_count++;

        offset += caplen;
    }

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddNumberToObject(json, "packets_loaded", packet_count);
    cJSON_AddStringToObject(json, "message", "PCAP file loaded successfully");
    send_json(c, 200, json);
    cJSON_Delete(json);
}

// API: POST /api/packet/inject - Inject/send packets to network
static void handle_api_packet_inject(struct mg_connection *c, struct mg_http_message *hm, server_t *srv) {
    // Parse JSON body
    cJSON *body = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!body) {
        send_error(c, 400, "Invalid JSON");
        return;
    }

    // Get device to inject on
    cJSON *device_json = cJSON_GetObjectItem(body, "device");
    const char *device = device_json && device_json->valuestring ?
                         device_json->valuestring : srv->current_device;

    if (!device || device[0] == '\0') {
        cJSON_Delete(body);
        send_error(c, 400, "No device specified");
        return;
    }

    // Get packet data (base64 encoded)
    cJSON *data_json = cJSON_GetObjectItem(body, "data");
    cJSON *packets_json = cJSON_GetObjectItem(body, "packets");

    // Get replay mode
    cJSON *replay_json = cJSON_GetObjectItem(body, "replay");
    bool replay_mode = replay_json && cJSON_IsTrue(replay_json);

    // Get repeat count
    cJSON *repeat_json = cJSON_GetObjectItem(body, "repeat");
    int repeat = (repeat_json && cJSON_IsNumber(repeat_json)) ? repeat_json->valueint : 1;
    if (repeat < 1) repeat = 1;
    if (repeat > 1000) repeat = 1000;

    int sent_count = 0;
    char error_msg[256] = "";

    // Open device for injection
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(device, 65536, 0, 1000, errbuf);
    if (!handle) {
        cJSON_Delete(body);
        snprintf(error_msg, sizeof(error_msg), "Failed to open device: %s", errbuf);
        send_error(c, 500, error_msg);
        return;
    }

    // Replay packets from buffer
    if (replay_mode && srv->config.packet_buffer) {
        uint64_t oldest = buffer_oldest_id(srv->config.packet_buffer);
        uint32_t count = buffer_count(srv->config.packet_buffer);

        // Get packet IDs to replay
        cJSON *from_json = cJSON_GetObjectItem(body, "from_id");
        cJSON *to_json = cJSON_GetObjectItem(body, "to_id");
        uint64_t from_id = from_json ? (uint64_t)from_json->valuedouble : oldest;
        uint64_t to_id = to_json ? (uint64_t)to_json->valuedouble : oldest + count - 1;

        packet_entry_t *entries;
        int num_packets = buffer_get_range(srv->config.packet_buffer, from_id, (uint32_t)(to_id - from_id + 1), &entries);

        if (num_packets > 0 && entries) {
            for (int r = 0; r < repeat; r++) {
                for (int i = 0; i < num_packets; i++) {
                    if (pcap_sendpacket(handle, entries[i].raw.data, entries[i].raw.caplen) == 0) {
                        sent_count++;
                    }
                }
            }
            buffer_free_entries(entries);
        }
    }
    // Send single packet (base64 encoded data)
    else if (data_json && data_json->valuestring) {
        // Decode base64
        size_t data_len = strlen(data_json->valuestring);
        size_t decoded_len = data_len * 3 / 4;
        uint8_t *decoded = malloc(decoded_len);

        if (decoded) {
            // Simple base64 decode
            mg_str b64 = mg_str(data_json->valuestring);
            int len = mg_base64_decode(b64.buf, b64.len, (char*)decoded, decoded_len);

            if (len > 0) {
                for (int r = 0; r < repeat; r++) {
                    if (pcap_sendpacket(handle, decoded, len) == 0) {
                        sent_count++;
                    }
                }
            }
            free(decoded);
        }
    }
    // Send multiple packets (array of base64)
    else if (packets_json && cJSON_IsArray(packets_json)) {
        cJSON *pkt_item;
        cJSON_ArrayForEach(pkt_item, packets_json) {
            if (pkt_item->valuestring) {
                size_t data_len = strlen(pkt_item->valuestring);
                size_t decoded_len = data_len * 3 / 4;
                uint8_t *decoded = malloc(decoded_len);

                if (decoded) {
                    mg_str b64 = mg_str(pkt_item->valuestring);
                    int len = mg_base64_decode(b64.buf, b64.len, (char*)decoded, decoded_len);

                    if (len > 0) {
                        for (int r = 0; r < repeat; r++) {
                            if (pcap_sendpacket(handle, decoded, len) == 0) {
                                sent_count++;
                            }
                        }
                    }
                    free(decoded);
                }
            }
        }
    }

    pcap_close(handle);
    cJSON_Delete(body);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "success", true);
    cJSON_AddNumberToObject(json, "packets_sent", sent_count);
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

    // Stop scanner if running
    if (srv->scanner) {
        scanner_stop(srv->scanner);
        scanner_destroy(srv->scanner);
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

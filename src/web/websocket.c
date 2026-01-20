/**
 * net-map - WebSocket handler for real-time packet streaming
 */

#include "server.h"
#include "mongoose.h"
#include "cJSON.h"
#include <stdio.h>

// WebSocket connections list
#define MAX_WS_CLIENTS 32

static struct mg_connection *ws_clients[MAX_WS_CLIENTS] = {0};
static int ws_client_count = 0;

void websocket_add_client(struct mg_connection *c) {
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (ws_clients[i] == NULL) {
            ws_clients[i] = c;
            ws_client_count++;
            printf("WebSocket client connected (%d total)\n", ws_client_count);
            return;
        }
    }
}

void websocket_remove_client(struct mg_connection *c) {
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (ws_clients[i] == c) {
            ws_clients[i] = NULL;
            ws_client_count--;
            printf("WebSocket client disconnected (%d total)\n", ws_client_count);
            return;
        }
    }
}

void websocket_broadcast_packet(const packet_entry_t *entry) {
    if (ws_client_count == 0) return;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "packet");
    cJSON_AddNumberToObject(json, "id", (double)entry->id);
    cJSON_AddNumberToObject(json, "timestamp", (double)entry->raw.timestamp_us);
    cJSON_AddNumberToObject(json, "length", entry->raw.caplen);
    cJSON_AddStringToObject(json, "src", entry->parsed.src_ip_str);
    cJSON_AddStringToObject(json, "dst", entry->parsed.dst_ip_str);
    cJSON_AddStringToObject(json, "protocol", entry->parsed.protocol_str);
    cJSON_AddStringToObject(json, "info", entry->parsed.info);

    char *str = cJSON_PrintUnformatted(json);
    size_t len = strlen(str);

    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (ws_clients[i] != NULL) {
            mg_ws_send(ws_clients[i], str, len, WEBSOCKET_OP_TEXT);
        }
    }

    free(str);
    cJSON_Delete(json);
}

void websocket_broadcast_stats(uint64_t packets, uint64_t bytes, bool capturing) {
    if (ws_client_count == 0) return;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "stats");
    cJSON_AddNumberToObject(json, "packets", (double)packets);
    cJSON_AddNumberToObject(json, "bytes", (double)bytes);
    cJSON_AddBoolToObject(json, "capturing", capturing);

    char *str = cJSON_PrintUnformatted(json);
    size_t len = strlen(str);

    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (ws_clients[i] != NULL) {
            mg_ws_send(ws_clients[i], str, len, WEBSOCKET_OP_TEXT);
        }
    }

    free(str);
    cJSON_Delete(json);
}

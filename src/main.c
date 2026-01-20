/**
 * net-map - Cross-platform packet sniffer with web UI
 *
 * Usage: net-map [options]
 *   -i <interface>  Network interface to capture on
 *   -p <port>       Web server port (default: 8080)
 *   -f <filter>     BPF filter expression
 *   -h              Show help
 */

#include "platform.h"
#include "capture.h"
#include "buffer.h"
#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define DEFAULT_PORT 8080
#define DEFAULT_BUFFER_SIZE 100000
#define STATIC_DIR "./static"

// Global state
static volatile bool g_running = true;
static packet_buffer_t *g_buffer = NULL;
static capture_handle_t *g_capture = NULL;
static server_t *g_server = NULL;

// Signal handler
static void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    g_running = false;
}

// Packet callback
static void packet_callback(const packet_t *pkt, void *user_data) {
    packet_buffer_t *buf = (packet_buffer_t*)user_data;
    buffer_push(buf, pkt);
}

static void print_usage(const char *prog) {
    printf("net-map - Cross-platform packet sniffer\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -i <interface>  Network interface to capture on\n");
    printf("  -p <port>       Web server port (default: %d)\n", DEFAULT_PORT);
    printf("  -f <filter>     BPF filter expression\n");
    printf("  -l              List available interfaces\n");
    printf("  -h              Show this help\n");
}

static void list_devices(void) {
    device_info_t *devices;
    int count = get_device_list(&devices);

    if (count < 0) {
        printf("Error: Failed to get device list\n");
        return;
    }

    if (count == 0) {
        printf("No network interfaces found\n");
        return;
    }

    printf("Available network interfaces:\n\n");
    for (int i = 0; i < count; i++) {
        printf("%d. %s\n", i + 1, devices[i].name);
        printf("   Description: %s\n", devices[i].description);
        if (devices[i].ip_addr[0]) {
            printf("   IP: %s\n", devices[i].ip_addr);
        }
        printf("   Status: %s%s\n",
               devices[i].is_up ? "UP" : "DOWN",
               devices[i].is_loopback ? " (loopback)" : "");
        printf("\n");
    }

    free_device_list(devices, count);
}

int main(int argc, char *argv[]) {
    char *interface = NULL;
    char *filter = NULL;
    int port = DEFAULT_PORT;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            filter = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0) {
            platform_init();
            list_devices();
            platform_cleanup();
            return 0;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Initialize platform
    if (platform_init() != 0) {
        fprintf(stderr, "Error: Platform initialization failed\n");
        return 1;
    }

    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Create packet buffer
    g_buffer = buffer_create(DEFAULT_BUFFER_SIZE);
    if (!g_buffer) {
        fprintf(stderr, "Error: Failed to create packet buffer\n");
        platform_cleanup();
        return 1;
    }

    // Open capture if interface specified
    if (interface) {
        g_capture = capture_open(interface, 65535, 1, 1000, errbuf);
        if (!g_capture) {
            fprintf(stderr, "Error: Failed to open interface '%s': %s\n", interface, errbuf);
            buffer_destroy(g_buffer);
            platform_cleanup();
            return 1;
        }

        if (filter) {
            if (capture_set_filter(g_capture, filter, errbuf) != 0) {
                fprintf(stderr, "Warning: Failed to set filter: %s\n", errbuf);
            }
        }

        if (capture_start(g_capture, packet_callback, g_buffer) != 0) {
            fprintf(stderr, "Error: Failed to start capture\n");
            capture_close(g_capture);
            buffer_destroy(g_buffer);
            platform_cleanup();
            return 1;
        }

        printf("Capturing on interface: %s\n", interface);
        if (filter) {
            printf("Filter: %s\n", filter);
        }
    } else {
        printf("No interface specified. Use -i to select an interface.\n");
        printf("Use -l to list available interfaces.\n\n");
    }

    // Create and start web server
    server_config_t config = {
        .port = port,
        .static_dir = STATIC_DIR,
        .packet_buffer = g_buffer,
        .capture = g_capture
    };

    g_server = server_create(&config);
    if (!g_server) {
        fprintf(stderr, "Error: Failed to create server\n");
        if (g_capture) capture_close(g_capture);
        buffer_destroy(g_buffer);
        platform_cleanup();
        return 1;
    }

    if (server_start(g_server) != 0) {
        fprintf(stderr, "Error: Failed to start server on port %d\n", port);
        server_destroy(g_server);
        if (g_capture) capture_close(g_capture);
        buffer_destroy(g_buffer);
        platform_cleanup();
        return 1;
    }

    printf("\nOpen http://localhost:%d in your browser\n", port);
    printf("Press Ctrl+C to stop\n\n");

    // Main loop
    while (g_running) {
        server_poll(g_server, 100);
    }

    // Cleanup
    printf("Cleaning up...\n");

    server_stop(g_server);
    server_destroy(g_server);

    if (g_capture) {
        capture_stop(g_capture);
        capture_close(g_capture);
    }

    buffer_destroy(g_buffer);
    platform_cleanup();

    printf("Done.\n");
    return 0;
}

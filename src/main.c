/**
 * net-map - Cross-platform packet sniffer with web UI
 *
 * Usage: net-map [options]
 *   -p <port>       Web server port (default: 8080)
 *   -l              List available interfaces
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

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

#define DEFAULT_PORT 8080
#define DEFAULT_BUFFER_SIZE 100000
#define STATIC_DIR "./static"

// Global state
static volatile bool g_running = true;
static packet_buffer_t *g_buffer = NULL;
static server_t *g_server = NULL;

// Signal handler
static void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    g_running = false;
}

static void print_usage(const char *prog) {
    printf("net-map - Cross-platform packet sniffer\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p <port>       Web server port (default: %d)\n", DEFAULT_PORT);
    printf("  -l              List available interfaces\n");
    printf("  -h              Show this help\n");
    printf("\nInterface selection is done via the web UI.\n");
}

static void open_browser(int port) {
#ifdef _WIN32
    char url[64];
    snprintf(url, sizeof(url), "http://localhost:%d", port);
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
#elif defined(__APPLE__)
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "open http://localhost:%d", port);
    system(cmd);
#else
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "xdg-open http://localhost:%d &", port);
    system(cmd);
#endif
}

static void print_local_ips(void) {
    device_info_t *devices;
    int count = get_device_list(&devices);
    if (count <= 0) return;

    printf("Local IP addresses:\n");
    for (int i = 0; i < count; i++) {
        if (devices[i].ip_addr[0] && !devices[i].is_loopback && devices[i].is_up) {
            printf("  - %s (%s)\n", devices[i].ip_addr, devices[i].description);
        }
    }
    free_device_list(devices, count);
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
    int port = DEFAULT_PORT;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
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

    // Create and start web server
    server_config_t config = {
        .port = port,
        .static_dir = STATIC_DIR,
        .packet_buffer = g_buffer
    };

    g_server = server_create(&config);
    if (!g_server) {
        fprintf(stderr, "Error: Failed to create server\n");
        buffer_destroy(g_buffer);
        platform_cleanup();
        return 1;
    }

    if (server_start(g_server) != 0) {
        fprintf(stderr, "Error: Failed to start server on port %d\n", port);
        server_destroy(g_server);
        buffer_destroy(g_buffer);
        platform_cleanup();
        return 1;
    }

    printf("\n========================================\n");
    printf("  Net-Map - Packet Sniffer\n");
    printf("========================================\n");
    printf("Web UI: http://localhost:%d\n\n", port);
    print_local_ips();
    printf("\nOpening browser...\n");
    printf("Press Ctrl+C to stop\n\n");

    // Auto-open browser
    open_browser(port);

    // Main loop
    while (g_running) {
        server_poll(g_server, 100);
    }

    // Cleanup
    printf("Cleaning up...\n");

    server_stop(g_server);
    server_destroy(g_server);
    buffer_destroy(g_buffer);
    platform_cleanup();

    printf("Done.\n");
    return 0;
}

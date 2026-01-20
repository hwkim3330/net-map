/**
 * net-map - Windows platform implementation
 */

#ifdef _WIN32

#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int platform_init(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return -1;
    }
    return 0;
}

void platform_cleanup(void) {
    WSACleanup();
}

int get_device_list(device_info_t **devices) {
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return -1;
    }

    // Count devices
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        count++;
    }

    if (count == 0) {
        pcap_freealldevs(alldevs);
        *devices = NULL;
        return 0;
    }

    // Allocate device array
    *devices = calloc(count, sizeof(device_info_t));
    if (!*devices) {
        pcap_freealldevs(alldevs);
        return -1;
    }

    // Fill device info
    int i = 0;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        device_info_t *info = &(*devices)[i];

        strncpy(info->name, dev->name, sizeof(info->name) - 1);

        if (dev->description) {
            strncpy(info->description, dev->description, sizeof(info->description) - 1);
        } else {
            strcpy(info->description, "Unknown");
        }

        // Get IP address
        pcap_addr_t *addr;
        for (addr = dev->addresses; addr != NULL; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                inet_ntop(AF_INET, &sin->sin_addr, info->ip_addr, sizeof(info->ip_addr));
                break;
            }
        }

        info->is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
        info->is_up = (dev->flags & PCAP_IF_UP) != 0;

        i++;
    }

    pcap_freealldevs(alldevs);

    return count;
}

void free_device_list(device_info_t *devices, int count) {
    (void)count;
    free(devices);
}

int thread_create(thread_t *thread, void *(*func)(void*), void *arg) {
    *thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
    return (*thread != NULL) ? 0 : -1;
}

int thread_join(thread_t thread) {
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}

uint64_t get_timestamp_us(void) {
    FILETIME ft;
    ULARGE_INTEGER ul;

    GetSystemTimeAsFileTime(&ft);
    ul.LowPart = ft.dwLowDateTime;
    ul.HighPart = ft.dwHighDateTime;

    // Convert from 100-nanosecond intervals since 1601 to microseconds since epoch
    return (ul.QuadPart - 116444736000000000ULL) / 10;
}

#endif // _WIN32

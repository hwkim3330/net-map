/**
 * net-map - Cross-platform packet sniffer
 * Platform abstraction layer
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <iphlpapi.h>

    #define SLEEP_MS(x) Sleep(x)
    #define PATH_SEP "\\"

    typedef HANDLE thread_t;
    typedef CRITICAL_SECTION mutex_t;

    #define mutex_init(m)    InitializeCriticalSection(m)
    #define mutex_lock(m)    EnterCriticalSection(m)
    #define mutex_unlock(m)  LeaveCriticalSection(m)
    #define mutex_destroy(m) DeleteCriticalSection(m)

#else
    #include <unistd.h>
    #include <pthread.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <ifaddrs.h>

    #define SLEEP_MS(x) usleep((x) * 1000)
    #define PATH_SEP "/"

    typedef pthread_t thread_t;
    typedef pthread_mutex_t mutex_t;

    #define mutex_init(m)    pthread_mutex_init(m, NULL)
    #define mutex_lock(m)    pthread_mutex_lock(m)
    #define mutex_unlock(m)  pthread_mutex_unlock(m)
    #define mutex_destroy(m) pthread_mutex_destroy(m)
#endif

#include <pcap.h>
#include <stdint.h>
#include <stdbool.h>

// Network device info
typedef struct {
    char name[256];
    char description[256];
    char ip_addr[64];
    char mac_addr[32];
    bool is_up;
    bool is_loopback;
} device_info_t;

// Platform functions
int platform_init(void);
void platform_cleanup(void);

// Device enumeration
int get_device_list(device_info_t **devices);
void free_device_list(device_info_t *devices, int count);

// Threading
int thread_create(thread_t *thread, void *(*func)(void*), void *arg);
int thread_join(thread_t thread);

// Time
uint64_t get_timestamp_us(void);

#endif // PLATFORM_H

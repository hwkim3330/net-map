/**
 * net-map - Packet capture implementation
 */

#include "capture.h"
#include "platform.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct capture_handle {
    pcap_t *pcap;
    char device[256];
    bool running;
    thread_t thread;
    packet_callback_t callback;
    void *user_data;
    capture_stats_t stats;
    mutex_t stats_mutex;
};

// Capture thread function
static void* capture_thread(void *arg) {
    capture_handle_t *handle = (capture_handle_t*)arg;
    struct pcap_pkthdr *header;
    const u_char *data;
    packet_t pkt;
    int ret;

    while (handle->running) {
        ret = pcap_next_ex(handle->pcap, &header, &data);

        if (ret == 1) {
            // Packet received
            pkt.timestamp_us = (uint64_t)header->ts.tv_sec * 1000000 + header->ts.tv_usec;
            pkt.caplen = header->caplen;
            pkt.origlen = header->len;

            if (pkt.caplen > MAX_PACKET_SIZE) {
                pkt.caplen = MAX_PACKET_SIZE;
            }
            memcpy(pkt.data, data, pkt.caplen);

            // Update stats
            mutex_lock(&handle->stats_mutex);
            handle->stats.packets_received++;
            handle->stats.bytes_received += pkt.caplen;
            mutex_unlock(&handle->stats_mutex);

            // Callback
            if (handle->callback) {
                handle->callback(&pkt, handle->user_data);
            }
        } else if (ret == 0) {
            // Timeout
            continue;
        } else if (ret == -2) {
            // EOF (reading from file)
            break;
        } else {
            // Error
            break;
        }
    }

    return NULL;
}

capture_handle_t* capture_open(const char *device, int snaplen, int promisc, int timeout_ms, char *errbuf) {
    capture_handle_t *handle = calloc(1, sizeof(capture_handle_t));
    if (!handle) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Memory allocation failed");
        return NULL;
    }

    handle->pcap = pcap_open_live(device, snaplen, promisc, timeout_ms, errbuf);
    if (!handle->pcap) {
        free(handle);
        return NULL;
    }

    strncpy(handle->device, device, sizeof(handle->device) - 1);
    mutex_init(&handle->stats_mutex);

    return handle;
}

void capture_close(capture_handle_t *handle) {
    if (!handle) return;

    capture_stop(handle);

    if (handle->pcap) {
        pcap_close(handle->pcap);
    }

    mutex_destroy(&handle->stats_mutex);
    free(handle);
}

int capture_set_filter(capture_handle_t *handle, const char *filter, char *errbuf) {
    struct bpf_program fp;

    if (!handle || !handle->pcap) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "Invalid handle");
        return -1;
    }

    if (pcap_compile(handle->pcap, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(handle->pcap));
        return -1;
    }

    if (pcap_setfilter(handle->pcap, &fp) == -1) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s", pcap_geterr(handle->pcap));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    return 0;
}

int capture_start(capture_handle_t *handle, packet_callback_t callback, void *user_data) {
    if (!handle || handle->running) {
        return -1;
    }

    handle->callback = callback;
    handle->user_data = user_data;
    handle->running = true;

    memset(&handle->stats, 0, sizeof(handle->stats));

    if (thread_create(&handle->thread, capture_thread, handle) != 0) {
        handle->running = false;
        return -1;
    }

    return 0;
}

void capture_stop(capture_handle_t *handle) {
    if (!handle || !handle->running) return;

    handle->running = false;

    // Break pcap loop
    if (handle->pcap) {
        pcap_breakloop(handle->pcap);
    }

    thread_join(handle->thread);
}

bool capture_is_running(capture_handle_t *handle) {
    return handle && handle->running;
}

int capture_get_stats(capture_handle_t *handle, capture_stats_t *stats) {
    if (!handle || !stats) return -1;

    struct pcap_stat ps;
    if (pcap_stats(handle->pcap, &ps) == 0) {
        mutex_lock(&handle->stats_mutex);
        stats->packets_received = handle->stats.packets_received;
        stats->bytes_received = handle->stats.bytes_received;
        stats->packets_dropped = ps.ps_drop;
        mutex_unlock(&handle->stats_mutex);
        return 0;
    }

    return -1;
}

int capture_next(capture_handle_t *handle, packet_t *pkt) {
    struct pcap_pkthdr *header;
    const u_char *data;

    if (!handle || !pkt) return -1;

    int ret = pcap_next_ex(handle->pcap, &header, &data);
    if (ret == 1) {
        pkt->timestamp_us = (uint64_t)header->ts.tv_sec * 1000000 + header->ts.tv_usec;
        pkt->caplen = header->caplen;
        pkt->origlen = header->len;

        if (pkt->caplen > MAX_PACKET_SIZE) {
            pkt->caplen = MAX_PACKET_SIZE;
        }
        memcpy(pkt->data, data, pkt->caplen);
        return 1;
    }

    return ret;
}

int capture_save_pcap(const char *filename, const packet_t *packets, int count) {
    pcap_t *dead;
    pcap_dumper_t *dumper;
    struct pcap_pkthdr header;

    dead = pcap_open_dead(DLT_EN10MB, MAX_PACKET_SIZE);
    if (!dead) return -1;

    dumper = pcap_dump_open(dead, filename);
    if (!dumper) {
        pcap_close(dead);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        header.ts.tv_sec = packets[i].timestamp_us / 1000000;
        header.ts.tv_usec = packets[i].timestamp_us % 1000000;
        header.caplen = packets[i].caplen;
        header.len = packets[i].origlen;

        pcap_dump((u_char*)dumper, &header, packets[i].data);
    }

    pcap_dump_close(dumper);
    pcap_close(dead);

    return 0;
}

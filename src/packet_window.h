#ifndef PACKET_WINDOW_H
#define PACKET_WINDOW_H

#include "packet_parser.h"
#include "traffic_stats.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define PACKET_WINDOW_SECONDS 5
#define PACKET_WINDOW_CAPACITY 16384

struct pkt_record {
    time_t ts;
    uint32_t size;
    uint8_t protocol;
};

struct packet_window {
    struct pkt_record records[PACKET_WINDOW_CAPACITY];
    size_t head;
    size_t count;
    int overflow_logged;

    uint64_t total_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t total_bytes;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
};

void packet_window_init(struct packet_window *win);

void packet_window_evict_expired(struct packet_window *win, time_t now);

void packet_window_push(struct packet_window *win,
                        const struct parsed_packet *packet, time_t now);

size_t packet_window_count(const struct packet_window *win);

void packet_window_snapshot(const struct packet_window *win,
                            struct traffic_stats *out);

#endif

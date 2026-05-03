#ifndef TRAFFIC_STATS_H
#define TRAFFIC_STATS_H

#include <stddef.h>
#include <stdint.h>

struct traffic_stats {
    uint64_t total_packets;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t total_bytes;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
};

void traffic_stats_init(struct traffic_stats *stats);
void traffic_stats_add_packet(struct traffic_stats *stats, uint8_t protocol, size_t packet_size);
void traffic_stats_reset(struct traffic_stats *stats);

#endif

#include "traffic_stats.h"

#include <string.h>

void traffic_stats_init(struct traffic_stats *stats) {
    if (stats == NULL) {
        return;
    }
    memset(stats, 0, sizeof(*stats));
}

void traffic_stats_add_packet(struct traffic_stats *stats, uint8_t protocol, size_t packet_size) {
    if (stats == NULL) {
        return;
    }

    stats->total_packets++;
    stats->total_bytes += (uint64_t)packet_size;

    if (protocol == 6) {
        stats->tcp_packets++;
        stats->tcp_bytes += (uint64_t)packet_size;
    } else if (protocol == 17) {
        stats->udp_packets++;
        stats->udp_bytes += (uint64_t)packet_size;
    }
}

void traffic_stats_reset(struct traffic_stats *stats) {
    traffic_stats_init(stats);
}

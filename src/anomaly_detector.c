#include "anomaly_detector.h"

#include <stdio.h>
#include <string.h>

#define UDP_PACKET_THRESHOLD 100
#define TCP_PACKET_THRESHOLD 150
#define BYTE_THRESHOLD 500000

static void set_alert(struct anomaly_alert *alert, const char *type, const char *severity,
                      const char *protocol, uint64_t packets, uint64_t bytes,
                      const char *description) {
    alert->type = type;
    alert->severity = severity;
    alert->protocol = protocol;
    alert->packet_count = packets;
    alert->bytes_count = bytes;
    strncpy(alert->description, description, sizeof(alert->description) - 1);
    alert->description[sizeof(alert->description) - 1] = '\0';
}

int anomaly_detector_check(const struct traffic_stats *window_stats,
                           struct anomaly_alert *alerts_out, int max_alerts) {
    int count = 0;
    char description[160];

    if (window_stats == NULL || alerts_out == NULL) {
        return 0;
    }

    if (window_stats->udp_packets > UDP_PACKET_THRESHOLD && count < max_alerts) {
        snprintf(description, sizeof(description),
                 "Possible UDP flood detected: udp_packets=%llu in window",
                 (unsigned long long)window_stats->udp_packets);
        set_alert(&alerts_out[count], "UDP_FLOOD_SUSPECTED", "HIGH", "UDP",
                  window_stats->udp_packets, window_stats->udp_bytes, description);
        count++;
    }

    if (window_stats->tcp_packets > TCP_PACKET_THRESHOLD && count < max_alerts) {
        snprintf(description, sizeof(description),
                 "Possible TCP spike detected: tcp_packets=%llu in window",
                 (unsigned long long)window_stats->tcp_packets);
        set_alert(&alerts_out[count], "TCP_SPIKE_SUSPECTED", "MEDIUM", "TCP",
                  window_stats->tcp_packets, window_stats->tcp_bytes, description);
        count++;
    }

    if (window_stats->total_bytes > BYTE_THRESHOLD && count < max_alerts) {
        snprintf(description, sizeof(description),
                 "High traffic volume detected: total_bytes=%llu in window",
                 (unsigned long long)window_stats->total_bytes);
        set_alert(&alerts_out[count], "HIGH_TRAFFIC_VOLUME", "MEDIUM", "UNKNOWN",
                  window_stats->total_packets, window_stats->total_bytes, description);
        count++;
    }

    return count;
}

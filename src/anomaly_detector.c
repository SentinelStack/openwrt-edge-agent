#include "anomaly_detector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define UDP_PACKET_THRESHOLD_DEFAULT 100
#define TCP_PACKET_THRESHOLD_DEFAULT 150
#define BYTE_THRESHOLD_DEFAULT 500000

static uint64_t env_threshold(const char *name, uint64_t fallback) {
    const char *value = getenv(name);
    char *end = NULL;
    unsigned long long parsed;

    if (value == NULL || value[0] == '\0') {
        return fallback;
    }
    parsed = strtoull(value, &end, 10);
    if (end == value || (end != NULL && *end != '\0') || parsed == 0) {
        return fallback;
    }
    return (uint64_t)parsed;
}

static uint64_t udp_packet_threshold(void) {
    return env_threshold("ANOMALY_UDP_PACKET_THRESHOLD", UDP_PACKET_THRESHOLD_DEFAULT);
}

static uint64_t tcp_packet_threshold(void) {
    return env_threshold("ANOMALY_TCP_PACKET_THRESHOLD", TCP_PACKET_THRESHOLD_DEFAULT);
}

static uint64_t byte_threshold(void) {
    return env_threshold("ANOMALY_BYTE_THRESHOLD", BYTE_THRESHOLD_DEFAULT);
}

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

    if (window_stats->udp_packets > udp_packet_threshold() && count < max_alerts) {
        snprintf(description, sizeof(description),
                 "Possible UDP flood detected: udp_packets=%llu in window",
                 (unsigned long long)window_stats->udp_packets);
        set_alert(&alerts_out[count], "UDP_FLOOD_SUSPECTED", "HIGH", "UDP",
                  window_stats->udp_packets, window_stats->udp_bytes, description);
        count++;
    }

    if (window_stats->tcp_packets > tcp_packet_threshold() && count < max_alerts) {
        snprintf(description, sizeof(description),
                 "Possible TCP spike detected: tcp_packets=%llu in window",
                 (unsigned long long)window_stats->tcp_packets);
        set_alert(&alerts_out[count], "TCP_SPIKE_SUSPECTED", "MEDIUM", "TCP",
                  window_stats->tcp_packets, window_stats->tcp_bytes, description);
        count++;
    }

    if (window_stats->total_bytes > byte_threshold() && count < max_alerts) {
        snprintf(description, sizeof(description),
                 "High traffic volume detected: total_bytes=%llu in window",
                 (unsigned long long)window_stats->total_bytes);
        set_alert(&alerts_out[count], "HIGH_TRAFFIC_VOLUME", "MEDIUM", "UNKNOWN",
                  window_stats->total_packets, window_stats->total_bytes, description);
        count++;
    }

    return count;
}

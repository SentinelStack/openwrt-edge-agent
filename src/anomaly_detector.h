#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "traffic_stats.h"

#include <stdint.h>

#define ANOMALY_MAX_ALERTS 3


struct anomaly_alert {
    const char *type;
    const char *severity;
    const char *protocol;
    uint64_t packet_count;
    uint64_t bytes_count;
    char description[160];
};


int anomaly_detector_check(const struct traffic_stats *window_stats,
                           struct anomaly_alert *alerts_out, int max_alerts);

/* Apply detector thresholds pulled from the backend ruleset. A value of 0
   leaves that dimension on its env/compiled default. Backend values take
   precedence over the ANOMALY_* environment variables. */
void anomaly_detector_set_thresholds(uint64_t udp_packets,
                                     uint64_t tcp_packets,
                                     uint64_t bytes);

#endif

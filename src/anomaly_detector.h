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

#endif

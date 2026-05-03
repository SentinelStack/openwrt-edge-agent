#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include "traffic_stats.h"

void anomaly_detector_check(const struct traffic_stats *window_stats);

#endif

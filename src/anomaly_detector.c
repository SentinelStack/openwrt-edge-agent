#include "anomaly_detector.h"

#include "logger.h"

#define UDP_PACKET_THRESHOLD 100
#define TCP_PACKET_THRESHOLD 150
#define BYTE_THRESHOLD 500000

void anomaly_detector_check(const struct traffic_stats *window_stats) {
    if (window_stats == NULL) {
        return;
    }

    if (window_stats->udp_packets > UDP_PACKET_THRESHOLD) {
        logger_alert("Possible UDP flood detected: udp_packets=%llu in last 5 seconds",
                     (unsigned long long)window_stats->udp_packets);
    }

    if (window_stats->tcp_packets > TCP_PACKET_THRESHOLD) {
        logger_alert("Possible TCP spike detected: tcp_packets=%llu in last 5 seconds",
                     (unsigned long long)window_stats->tcp_packets);
    }

    if (window_stats->total_bytes > BYTE_THRESHOLD) {
        logger_alert("High traffic volume detected: total_bytes=%llu in last 5 seconds",
                     (unsigned long long)window_stats->total_bytes);
    }
}

#ifndef BACKEND_CLIENT_H
#define BACKEND_CLIENT_H

#include "anomaly_detector.h"
#include "flow_table.h"
#include "traffic_stats.h"


struct backend_config {
    int enabled;
    char scheme[8]; /* "https" (default) or "http" */
    char host[128];
    int port;
    char device_id[64];
    char device_id_path[256]; 
    char device_name[64];
    char device_ip[16];
    char firmware[64];
    char model[64];
};


int backend_config_load(struct backend_config *cfg);


int backend_register(struct backend_config *cfg);


int backend_send_heartbeat(const struct backend_config *cfg);


int backend_send_traffic(const struct backend_config *cfg,
                         const struct traffic_stats *stats,
                         int window_seconds, const char *timestamp);


int backend_send_alert(const struct backend_config *cfg,
                       const struct anomaly_alert *alert,
                       const struct flow_entry *flow,
                       int window_seconds, const char *timestamp);

#endif

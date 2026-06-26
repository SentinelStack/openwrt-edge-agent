#ifndef UPLOADER_H
#define UPLOADER_H

#include "anomaly_detector.h"
#include "backend_client.h"
#include "client_roster.h"
#include "dns_window.h"
#include "flow_table.h"
#include "fx_ring.h"
#include "traffic_stats.h"

struct upload_job {
    struct traffic_stats stats;
    int window_seconds;
    char timestamp[32];

    int alert_count;
    struct anomaly_alert alerts[ANOMALY_MAX_ALERTS];
    struct flow_entry alert_flow[ANOMALY_MAX_ALERTS];
    int alert_has_flow[ANOMALY_MAX_ALERTS];

    int dns_count;
    struct dns_event dns_events[DNS_MAX_EVENTS];

    int client_count;
    struct client_entry clients[CLIENT_MAX];

    int fx_count;
    struct fx_packet fx_packets[FX_SAMPLE_MAX];

    int send_heartbeat;
    int sync_ruleset;
};

int uploader_start(const struct backend_config *backend);

void uploader_submit(const struct upload_job *job);

void uploader_stop(void);

#endif

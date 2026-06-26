#include "anomaly_detector.h"
#include "backend_client.h"
#include "client_roster.h"
#include "dns_window.h"
#include "flow_table.h"
#include "iso_time.h"
#include "logger.h"
#include "packet_capture.h"
#include "packet_parser.h"
#include "packet_window.h"
#include "rules_client.h"
#include "traffic_stats.h"
#include "uploader.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 65536
#define STATS_WINDOW_SECONDS 5
#define RULES_SYNC_SECONDS 60

enum filter_mode {
    FILTER_BOTH = 0,
    FILTER_TCP = 1,
    FILTER_UDP = 2
};

static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s [--tcp|--udp|--help]\n", prog);
    printf("  %s         Process TCP and UDP traffic\n", prog);
    printf("  %s --tcp   Process TCP traffic only\n", prog);
    printf("  %s --udp   Process UDP traffic only\n", prog);
    printf("  %s --help  Show this message\n", prog);
}

static int should_process_packet(enum filter_mode mode, unsigned int protocol) {
    if (mode == FILTER_TCP && protocol != PROTO_TCP) {
        return 0;
    }
    if (mode == FILTER_UDP && protocol != PROTO_UDP) {
        return 0;
    }
    return 1;
}


static uint8_t protocol_for_alert(const char *protocol) {
    if (strcmp(protocol, "TCP") == 0) {
        return PROTO_TCP;
    }
    if (strcmp(protocol, "UDP") == 0) {
        return PROTO_UDP;
    }
    return 0;
}

static void flush_window(const struct traffic_stats *window_stats,
                         const struct flow_table *flows,
                         const struct dns_window *dns,
                         int window_seconds, time_t now, int sync_rules) {
    struct upload_job job;
    char timestamp[32];
    int alert_count;
    int i;

    memset(&job, 0, sizeof(job));
    iso_time_format(now, timestamp, sizeof(timestamp));

    job.stats = *window_stats;
    job.window_seconds = window_seconds;
    strncpy(job.timestamp, timestamp, sizeof(job.timestamp) - 1);
    job.send_heartbeat = 1;
    job.sync_ruleset = sync_rules;

    alert_count = anomaly_detector_check(window_stats, job.alerts, ANOMALY_MAX_ALERTS);
    job.alert_count = alert_count;
    for (i = 0; i < alert_count; i++) {
        const struct flow_entry *flow = flow_table_top(flows, protocol_for_alert(job.alerts[i].protocol));
        logger_alert("%s", job.alerts[i].description);
        if (flow != NULL) {
            job.alert_flow[i] = *flow;
            job.alert_has_flow[i] = 1;
        }
    }

    if (dns != NULL && dns->count > 0) {
        memcpy(job.dns_events, dns->events, dns->count * sizeof(struct dns_event));
        job.dns_count = (int)dns->count;
    }

    {
        struct client_roster roster;
        client_roster_collect(&roster);
        if (roster.count > 0) {
            memcpy(job.clients, roster.entries, roster.count * sizeof(struct client_entry));
            job.client_count = (int)roster.count;
        }
    }

    uploader_submit(&job);
}

/* Pull the device's detection ruleset from the backend and apply its
   thresholds to the local anomaly detector. */
static void sync_ruleset(const struct backend_config *backend) {
    struct agent_ruleset ruleset;

    if (!backend->enabled || backend->device_id[0] == '\0') {
        return;
    }
    if (rules_client_fetch(backend, &ruleset) == 0) {
        anomaly_detector_set_thresholds(ruleset.udp_packet_threshold,
                                        ruleset.tcp_packet_threshold,
                                        ruleset.byte_threshold);
    }
}

static void log_stats_window(const struct traffic_stats *stats) {
    logger_info("[STATS] total_packets=%llu tcp=%llu udp=%llu total_bytes=%llu tcp_bytes=%llu udp_bytes=%llu",
                (unsigned long long)stats->total_packets,
                (unsigned long long)stats->tcp_packets,
                (unsigned long long)stats->udp_packets,
                (unsigned long long)stats->total_bytes,
                (unsigned long long)stats->tcp_bytes,
                (unsigned long long)stats->udp_bytes);
}

int main(int argc, char *argv[]) {
    enum filter_mode mode = FILTER_BOTH;
    int capture_fd = -1;
    unsigned char buffer[BUFFER_SIZE];
    static struct flow_table flows;
    static struct dns_window dns;
    static struct packet_window pkt_window;
    struct backend_config backend;
    time_t window_start = 0;
    time_t last_rules_sync = 0;
    const char *log_packets_env = NULL;
    int log_packets = 0;

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (argc == 2 && strcmp(argv[1], "--tcp") == 0) {
        mode = FILTER_TCP;
    } else if (argc == 2 && strcmp(argv[1], "--udp") == 0) {
        mode = FILTER_UDP;
    } else if (argc > 1) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    capture_fd = packet_capture_open();
    if (capture_fd < 0) {
        perror("packet_capture_open");
        return EXIT_FAILURE;
    }

    flow_table_init(&flows);
    dns_window_init(&dns);
    packet_window_init(&pkt_window);
    window_start = time(NULL);
    log_packets_env = getenv("AGENT_LOG_PACKETS");
    log_packets = (log_packets_env != NULL && log_packets_env[0] != '\0');
    logger_info("openwrt-agent started (per-packet logging %s)", log_packets ? "on" : "off");

    backend_config_load(&backend);
    if (backend.enabled) {
        logger_info("[BACKEND] target http://%s:%d", backend.host, backend.port);
        if (backend_register(&backend) != 0) {
            logger_info("[BACKEND] registration failed; continuing in local-only mode");
        }
        // Pull the detection ruleset (TLS GET) and apply it — independent of
        // registration, so it works even where register (plain POST) can't.
        sync_ruleset(&backend);
    } else {
        logger_info("[BACKEND] disabled (set BACKEND_HOST to enable telemetry upload)");
    }
    last_rules_sync = time(NULL);

    if (uploader_start(&backend) != 0) {
        logger_info("[BACKEND] uploader thread failed to start; telemetry upload disabled");
    }

    while (keep_running) {
        ssize_t bytes_read = packet_capture_receive(capture_fd, buffer, sizeof(buffer));
        struct parsed_packet packet;
        time_t now = 0;

        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("packet_capture_receive");
            packet_capture_close(capture_fd);
            return EXIT_FAILURE;
        }

        if (!parse_packet(buffer, (size_t)bytes_read, &packet)) {
            continue;
        }

        if (!should_process_packet(mode, packet.protocol)) {
            continue;
        }

        now = time(NULL);
        flow_table_add(&flows, &packet);
        if (packet.is_dns_query) {
            dns_window_add(&dns, packet.src_ip, packet.dns_qname);
        }
        packet_window_push(&pkt_window, &packet, now);
        if (log_packets) {
            logger_packet(packet.protocol == PROTO_TCP ? "TCP" : "UDP",
                          packet.src_ip,
                          packet.src_port,
                          packet.dst_ip,
                          packet.dst_port,
                          (unsigned int)packet.packet_size);
        }

        if ((now - window_start) >= STATS_WINDOW_SECONDS) {
            struct traffic_stats rolling;
            int sync_rules;

            packet_window_snapshot(&pkt_window, &rolling);
            log_stats_window(&rolling);
            sync_rules = ((now - last_rules_sync) >= RULES_SYNC_SECONDS);
            flush_window(&rolling, &flows, &dns, (int)(now - window_start), now, sync_rules);
            if (sync_rules) {
                last_rules_sync = now;
            }
            flow_table_reset(&flows);
            dns_window_reset(&dns);
            window_start = now;
        }
    }

    logger_info("openwrt-agent stopped");
    uploader_stop();
    packet_capture_close(capture_fd);
    return EXIT_SUCCESS;
}

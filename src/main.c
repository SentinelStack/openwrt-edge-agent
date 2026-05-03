#include "anomaly_detector.h"
#include "logger.h"
#include "packet_capture.h"
#include "packet_parser.h"
#include "traffic_stats.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 65536
#define STATS_WINDOW_SECONDS 5

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
    struct traffic_stats window_stats;
    time_t window_start = 0;

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

    traffic_stats_init(&window_stats);
    window_start = time(NULL);
    logger_info("openwrt-agent started");

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

        traffic_stats_add_packet(&window_stats, packet.protocol, packet.packet_size);
        logger_packet(packet.protocol == PROTO_TCP ? "TCP" : "UDP",
                      packet.src_ip,
                      packet.src_port,
                      packet.dst_ip,
                      packet.dst_port,
                      (unsigned int)packet.packet_size);

        now = time(NULL);
        if ((now - window_start) >= STATS_WINDOW_SECONDS) {
            log_stats_window(&window_stats);
            anomaly_detector_check(&window_stats);
            traffic_stats_reset(&window_stats);
            window_start = now;
        }
    }

    logger_info("openwrt-agent stopped");
    packet_capture_close(capture_fd);
    return EXIT_SUCCESS;
}

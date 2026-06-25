#include "packet_window.h"

#include "logger.h"

#include <string.h>

void packet_window_init(struct packet_window *win) {
    if (win == NULL) {
        return;
    }
    memset(win, 0, sizeof(*win));
}

static void aggregate(struct packet_window *win, const struct pkt_record *rec, int sign) {
    win->total_packets += (uint64_t)sign;
    win->total_bytes += (uint64_t)(sign * (int64_t)rec->size);

    if (rec->protocol == PROTO_TCP) {
        win->tcp_packets += (uint64_t)sign;
        win->tcp_bytes += (uint64_t)(sign * (int64_t)rec->size);
    } else if (rec->protocol == PROTO_UDP) {
        win->udp_packets += (uint64_t)sign;
        win->udp_bytes += (uint64_t)(sign * (int64_t)rec->size);
    }
}

static void pop_head(struct packet_window *win) {
    aggregate(win, &win->records[win->head], -1);
    win->head = (win->head + 1) % PACKET_WINDOW_CAPACITY;
    win->count--;
}

void packet_window_evict_expired(struct packet_window *win, time_t now) {
    time_t cutoff;

    if (win == NULL) {
        return;
    }

    cutoff = now - PACKET_WINDOW_SECONDS;
    while (win->count > 0 && win->records[win->head].ts < cutoff) {
        pop_head(win);
    }

    if (win->count == 0) {
        win->overflow_logged = 0;
    }
}

void packet_window_push(struct packet_window *win,
                        const struct parsed_packet *packet, time_t now) {
    size_t tail;
    struct pkt_record *slot;

    if (win == NULL || packet == NULL) {
        return;
    }

    packet_window_evict_expired(win, now);

    if (win->count == PACKET_WINDOW_CAPACITY) {
        if (!win->overflow_logged) {
            logger_info("packet window saturated (%d packets in <%ds); dropping oldest",
                        PACKET_WINDOW_CAPACITY, PACKET_WINDOW_SECONDS);
            win->overflow_logged = 1;
        }
        pop_head(win);
    }

    tail = (win->head + win->count) % PACKET_WINDOW_CAPACITY;
    slot = &win->records[tail];
    slot->ts = now;
    slot->size = (uint32_t)packet->packet_size;
    slot->protocol = packet->protocol;
    win->count++;

    aggregate(win, slot, +1);
}

size_t packet_window_count(const struct packet_window *win) {
    return win == NULL ? 0 : win->count;
}

void packet_window_snapshot(const struct packet_window *win, struct traffic_stats *out) {
    if (out == NULL) {
        return;
    }
    traffic_stats_init(out);
    if (win == NULL) {
        return;
    }
    out->total_packets = win->total_packets;
    out->tcp_packets = win->tcp_packets;
    out->udp_packets = win->udp_packets;
    out->total_bytes = win->total_bytes;
    out->tcp_bytes = win->tcp_bytes;
    out->udp_bytes = win->udp_bytes;
}

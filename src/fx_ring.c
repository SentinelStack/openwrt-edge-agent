#include "fx_ring.h"

#include <string.h>

void fx_ring_init(struct fx_ring *r) {
    if (r == NULL) {
        return;
    }
    memset(r, 0, sizeof(*r));
}

void fx_ring_push(struct fx_ring *r, const struct parsed_packet *p, time_t now) {
    size_t tail;
    struct fx_packet *slot;

    if (r == NULL || p == NULL) {
        return;
    }

    tail = (r->head + r->count) % FX_RING_MAX;
    if (r->count == FX_RING_MAX) {
        r->head = (r->head + 1) % FX_RING_MAX;
    } else {
        r->count++;
    }

    slot = &r->packets[tail];
    memset(slot, 0, sizeof(*slot));
    slot->ts = now;
    strncpy(slot->src_ip, p->src_ip, sizeof(slot->src_ip) - 1);
    strncpy(slot->dst_ip, p->dst_ip, sizeof(slot->dst_ip) - 1);
    slot->src_port = p->src_port;
    slot->dst_port = p->dst_port;
    slot->protocol = p->protocol;
    slot->size = (uint32_t)p->packet_size;
}

int fx_ring_recent(const struct fx_ring *r, struct fx_packet *out, int max) {
    int want;
    int i;

    if (r == NULL || out == NULL || max <= 0) {
        return 0;
    }

    want = (int)r->count;
    if (want > max) {
        want = max;
    }

    for (i = 0; i < want; i++) {
        size_t idx = (r->head + r->count - 1 - (size_t)i) % FX_RING_MAX;
        out[i] = r->packets[idx];
    }

    return want;
}

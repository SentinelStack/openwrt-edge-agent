#ifndef FX_RING_H
#define FX_RING_H

#include "packet_parser.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct fx_packet {
    time_t ts;
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t size;
};

#define FX_RING_MAX 256
#define FX_SAMPLE_MAX 32

struct fx_ring {
    struct fx_packet packets[FX_RING_MAX];
    size_t head;
    size_t count;
};

void fx_ring_init(struct fx_ring *r);

void fx_ring_push(struct fx_ring *r, const struct parsed_packet *p, time_t now);

int fx_ring_recent(const struct fx_ring *r, struct fx_packet *out, int max);

#endif

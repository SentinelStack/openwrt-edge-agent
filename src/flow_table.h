#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "packet_parser.h"

#include <stddef.h>
#include <stdint.h>


struct flow_entry {
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t packets;
    uint64_t bytes;
};

#define FLOW_TABLE_CAPACITY 2048


struct flow_table {
    struct flow_entry entries[FLOW_TABLE_CAPACITY];
    size_t count;
    int overflow_logged;
};

void flow_table_init(struct flow_table *table);

void flow_table_add(struct flow_table *table, const struct parsed_packet *packet);


const struct flow_entry *flow_table_top(const struct flow_table *table, uint8_t protocol);

/* Largest number of distinct destination ports contacted by any single source
   IP in the current window (the port-scan signal). Copies the offending source
   IP and a sample target IP into the out buffers. Returns 0 for an empty table. */
size_t flow_table_port_fanout(const struct flow_table *table,
                              char *out_src_ip, size_t src_len,
                              char *out_dst_ip, size_t dst_len);

void flow_table_reset(struct flow_table *table);

#endif

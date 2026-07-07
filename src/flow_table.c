#include "flow_table.h"

#include "logger.h"

#include <string.h>

void flow_table_init(struct flow_table *table) {
    if (table == NULL) {
        return;
    }
    memset(table, 0, sizeof(*table));
}

static int flow_matches(const struct flow_entry *entry, const struct parsed_packet *packet) {
    return entry->protocol == packet->protocol &&
           entry->src_port == packet->src_port &&
           entry->dst_port == packet->dst_port &&
           strncmp(entry->src_ip, packet->src_ip, sizeof(entry->src_ip)) == 0 &&
           strncmp(entry->dst_ip, packet->dst_ip, sizeof(entry->dst_ip)) == 0;
}

void flow_table_add(struct flow_table *table, const struct parsed_packet *packet) {
    size_t i;
    struct flow_entry *slot = NULL;

    if (table == NULL || packet == NULL) {
        return;
    }

    for (i = 0; i < table->count; i++) {
        if (flow_matches(&table->entries[i], packet)) {
            table->entries[i].packets++;
            table->entries[i].bytes += (uint64_t)packet->packet_size;
            return;
        }
    }

    if (table->count >= FLOW_TABLE_CAPACITY) {
        if (!table->overflow_logged) {
            logger_info("flow table full (%d entries); new flows dropped until next window", FLOW_TABLE_CAPACITY);
            table->overflow_logged = 1;
        }
        return;
    }

    slot = &table->entries[table->count];
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->src_ip, packet->src_ip, sizeof(slot->src_ip) - 1);
    strncpy(slot->dst_ip, packet->dst_ip, sizeof(slot->dst_ip) - 1);
    slot->src_port = packet->src_port;
    slot->dst_port = packet->dst_port;
    slot->protocol = packet->protocol;
    slot->packets = 1;
    slot->bytes = (uint64_t)packet->packet_size;
    table->count++;
}

const struct flow_entry *flow_table_top(const struct flow_table *table, uint8_t protocol) {
    size_t i;
    const struct flow_entry *best = NULL;

    if (table == NULL) {
        return NULL;
    }

    for (i = 0; i < table->count; i++) {
        const struct flow_entry *entry = &table->entries[i];
        if (protocol != 0 && entry->protocol != protocol) {
            continue;
        }
        if (best == NULL || entry->packets > best->packets) {
            best = entry;
        }
    }

    return best;
}

size_t flow_table_port_fanout(const struct flow_table *table,
                              char *out_src_ip, size_t src_len,
                              char *out_dst_ip, size_t dst_len) {
    /* 65536-bit bitmap of destination ports seen for one source. The capture
       loop is single-threaded, so a static scratch buffer is safe and keeps it
       off the stack. */
    static uint8_t seen[8192];
    size_t best = 0;
    size_t i;
    size_t j;

    if (table == NULL) {
        return 0;
    }

    for (i = 0; i < table->count; i++) {
        const struct flow_entry *e = &table->entries[i];
        const char *sample_dst = e->dst_ip;
        size_t distinct = 0;
        int src_seen = 0;

        /* Score each distinct source IP only once. */
        for (j = 0; j < i; j++) {
            if (strncmp(table->entries[j].src_ip, e->src_ip, sizeof(e->src_ip)) == 0) {
                src_seen = 1;
                break;
            }
        }
        if (src_seen) {
            continue;
        }

        memset(seen, 0, sizeof(seen));
        for (j = 0; j < table->count; j++) {
            const struct flow_entry *f = &table->entries[j];
            uint16_t port;

            if (strncmp(f->src_ip, e->src_ip, sizeof(e->src_ip)) != 0) {
                continue;
            }
            port = f->dst_port;
            if ((seen[port >> 3] & (uint8_t)(1u << (port & 7))) == 0) {
                seen[port >> 3] |= (uint8_t)(1u << (port & 7));
                distinct++;
                sample_dst = f->dst_ip;
            }
        }

        if (distinct > best) {
            best = distinct;
            if (out_src_ip != NULL && src_len > 0) {
                strncpy(out_src_ip, e->src_ip, src_len - 1);
                out_src_ip[src_len - 1] = '\0';
            }
            if (out_dst_ip != NULL && dst_len > 0) {
                strncpy(out_dst_ip, sample_dst, dst_len - 1);
                out_dst_ip[dst_len - 1] = '\0';
            }
        }
    }

    return best;
}

void flow_table_reset(struct flow_table *table) {
    flow_table_init(table);
}

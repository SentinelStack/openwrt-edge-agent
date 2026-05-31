#include "flow_table.h"

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

void flow_table_reset(struct flow_table *table) {
    flow_table_init(table);
}

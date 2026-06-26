#include "client_roster.h"

#include <stdio.h>
#include <string.h>

#define DHCP_LEASES_FILE "/tmp/dhcp.leases"
#define ARP_FILE "/proc/net/arp"

static struct client_entry *roster_find_by_ip(struct client_roster *roster, const char *ip) {
    size_t i;

    for (i = 0; i < roster->count; i++) {
        if (strncmp(roster->entries[i].ip, ip, sizeof(roster->entries[i].ip)) == 0) {
            return &roster->entries[i];
        }
    }
    return NULL;
}

static void read_dhcp_leases(struct client_roster *roster) {
    FILE *fp = NULL;
    char line[256];

    fp = fopen(DHCP_LEASES_FILE, "r");
    if (fp == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char expiry[32];
        char mac[20];
        char ip[16];
        char hostname[64];
        struct client_entry *slot = NULL;

        expiry[0] = '\0';
        mac[0] = '\0';
        ip[0] = '\0';
        hostname[0] = '\0';

        if (sscanf(line, "%31s %19s %15s %63s", expiry, mac, ip, hostname) < 3) {
            continue;
        }
        if (ip[0] == '\0' || mac[0] == '\0') {
            continue;
        }
        if (roster->count >= CLIENT_MAX) {
            break;
        }

        slot = &roster->entries[roster->count];
        memset(slot, 0, sizeof(*slot));
        strncpy(slot->ip, ip, sizeof(slot->ip) - 1);
        strncpy(slot->mac, mac, sizeof(slot->mac) - 1);
        if (hostname[0] != '\0' && strcmp(hostname, "*") != 0) {
            strncpy(slot->name, hostname, sizeof(slot->name) - 1);
        }
        slot->online = 0;
        roster->count++;
    }

    fclose(fp);
}

static void read_arp_flags(struct client_roster *roster) {
    FILE *fp = NULL;
    char line[256];
    int first = 1;

    fp = fopen(ARP_FILE, "r");
    if (fp == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char ip[16];
        char hwtype[16];
        unsigned int flags = 0;
        struct client_entry *entry = NULL;

        if (first) {
            first = 0;
            continue;
        }

        ip[0] = '\0';
        hwtype[0] = '\0';

        if (sscanf(line, "%15s %15s 0x%x", ip, hwtype, &flags) < 3) {
            continue;
        }
        if (ip[0] == '\0') {
            continue;
        }

        entry = roster_find_by_ip(roster, ip);
        if (entry != NULL && (flags & 0x2) != 0) {
            entry->online = 1;
        }
    }

    fclose(fp);
}

void client_roster_collect(struct client_roster *out) {
    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    read_dhcp_leases(out);
    read_arp_flags(out);
}

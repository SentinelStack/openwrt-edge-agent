#include "client_roster.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DHCP_LEASES_FILE "/tmp/dhcp.leases"
#define CLIENT_ONLINE_WINDOW_SECONDS 60

static int is_private_ip(const char *ip) {
    if (strncmp(ip, "192.168.", 8) == 0) {
        return 1;
    }
    if (strncmp(ip, "10.", 3) == 0) {
        return 1;
    }
    if (strncmp(ip, "172.", 4) == 0) {
        int second = atoi(ip + 4);
        if (second >= 16 && second <= 31) {
            return 1;
        }
    }
    return 0;
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

void client_activity_init(struct client_activity *activity) {
    if (activity != NULL) {
        memset(activity, 0, sizeof(*activity));
    }
}

void client_activity_touch(struct client_activity *activity, const char *ip, time_t now) {
    size_t i;
    size_t oldest = 0;
    struct client_activity_entry *slot = NULL;

    if (activity == NULL || ip == NULL || ip[0] == '\0' || !is_private_ip(ip)) {
        return;
    }

    for (i = 0; i < activity->count; i++) {
        if (strncmp(activity->entries[i].ip, ip, sizeof(activity->entries[i].ip)) == 0) {
            activity->entries[i].last_seen = now;
            return;
        }
    }

    if (activity->count < CLIENT_ACTIVITY_MAX) {
        slot = &activity->entries[activity->count];
        memset(slot, 0, sizeof(*slot));
        strncpy(slot->ip, ip, sizeof(slot->ip) - 1);
        slot->last_seen = now;
        activity->count++;
        return;
    }

    for (i = 1; i < activity->count; i++) {
        if (activity->entries[i].last_seen < activity->entries[oldest].last_seen) {
            oldest = i;
        }
    }
    memset(&activity->entries[oldest], 0, sizeof(activity->entries[oldest]));
    strncpy(activity->entries[oldest].ip, ip, sizeof(activity->entries[oldest].ip) - 1);
    activity->entries[oldest].last_seen = now;
}

static int activity_is_online(const struct client_activity *activity, const char *ip, time_t now) {
    size_t i;

    if (activity == NULL) {
        return 0;
    }
    for (i = 0; i < activity->count; i++) {
        if (strncmp(activity->entries[i].ip, ip, sizeof(activity->entries[i].ip)) == 0) {
            return (now - activity->entries[i].last_seen) <= CLIENT_ONLINE_WINDOW_SECONDS;
        }
    }
    return 0;
}

void client_roster_collect(struct client_roster *out, const struct client_activity *activity, time_t now) {
    size_t i;

    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    read_dhcp_leases(out);
    for (i = 0; i < out->count; i++) {
        out->entries[i].online = activity_is_online(activity, out->entries[i].ip, now);
    }
}

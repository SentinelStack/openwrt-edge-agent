#ifndef CLIENT_ROSTER_H
#define CLIENT_ROSTER_H

#include <stddef.h>
#include <time.h>

struct client_entry {
    char ip[16];
    char mac[20];
    char name[64];
    int online;
};

#define CLIENT_MAX 64

struct client_roster {
    struct client_entry entries[CLIENT_MAX];
    size_t count;
};

struct client_activity_entry {
    char ip[16];
    time_t last_seen;
};

#define CLIENT_ACTIVITY_MAX 256

struct client_activity {
    struct client_activity_entry entries[CLIENT_ACTIVITY_MAX];
    size_t count;
};

void client_activity_init(struct client_activity *activity);

void client_activity_touch(struct client_activity *activity, const char *ip, time_t now);

void client_roster_collect(struct client_roster *out, const struct client_activity *activity, time_t now);

#endif

#ifndef CLIENT_ROSTER_H
#define CLIENT_ROSTER_H

#include <stddef.h>

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

void client_roster_collect(struct client_roster *out);

#endif

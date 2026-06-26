#ifndef DNS_WINDOW_H
#define DNS_WINDOW_H

#include <stddef.h>
#include <stdint.h>

struct dns_event {
    char client_ip[16];
    char domain[256];
    uint32_t count;
};

#define DNS_MAX_EVENTS 64

struct dns_window {
    struct dns_event events[DNS_MAX_EVENTS];
    size_t count;
    int overflow_logged;
};

void dns_window_init(struct dns_window *win);

void dns_window_add(struct dns_window *win, const char *client_ip, const char *domain);

void dns_window_reset(struct dns_window *win);

#endif

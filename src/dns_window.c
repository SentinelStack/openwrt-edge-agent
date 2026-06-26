#include "dns_window.h"

#include "logger.h"

#include <string.h>

void dns_window_init(struct dns_window *win) {
    if (win == NULL) {
        return;
    }
    memset(win, 0, sizeof(*win));
}

void dns_window_add(struct dns_window *win, const char *client_ip, const char *domain) {
    size_t i;
    struct dns_event *slot = NULL;

    if (win == NULL || client_ip == NULL || domain == NULL) {
        return;
    }

    for (i = 0; i < win->count; i++) {
        if (strncmp(win->events[i].client_ip, client_ip, sizeof(win->events[i].client_ip)) == 0 &&
            strncmp(win->events[i].domain, domain, sizeof(win->events[i].domain)) == 0) {
            win->events[i].count++;
            return;
        }
    }

    if (win->count >= DNS_MAX_EVENTS) {
        if (!win->overflow_logged) {
            logger_info("dns window full (%d events); new queries dropped until next window", DNS_MAX_EVENTS);
            win->overflow_logged = 1;
        }
        return;
    }

    slot = &win->events[win->count];
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->client_ip, client_ip, sizeof(slot->client_ip) - 1);
    strncpy(slot->domain, domain, sizeof(slot->domain) - 1);
    slot->count = 1;
    win->count++;
}

void dns_window_reset(struct dns_window *win) {
    dns_window_init(win);
}

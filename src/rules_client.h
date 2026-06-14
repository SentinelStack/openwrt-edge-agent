#ifndef RULES_CLIENT_H
#define RULES_CLIENT_H

#include "backend_client.h"

#include <stdint.h>

/* Detection thresholds pulled from the backend ruleset. A value of 0 means the
   backend did not specify that key, so the detector keeps its env/default. */
struct agent_ruleset {
    int loaded;
    uint64_t udp_packet_threshold;
    uint64_t tcp_packet_threshold;
    uint64_t byte_threshold;
    char version[48];
};

/* Fetch GET /api/devices/{deviceId}/ruleset and parse the detector thresholds.
   Returns 0 on success (out->loaded set to 1), -1 otherwise. */
int rules_client_fetch(const struct backend_config *cfg, struct agent_ruleset *out);

#endif

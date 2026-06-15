#include "rules_client.h"

#include "http_client.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RULESET_RESP_MAX 8192

/* Parse an unsigned integer value for "key" out of a flat-ish JSON blob.
   Returns 0 and sets *out when found, -1 otherwise. */
static int extract_json_number(const char *json, const char *key, uint64_t *out) {
    char pattern[64];
    const char *p = NULL;

    if (json == NULL || key == NULL || out == NULL) {
        return -1;
    }
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (p == NULL) {
        return -1;
    }
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t') {
        p++;
    }
    if (*p < '0' || *p > '9') {
        return -1;
    }
    *out = strtoull(p, NULL, 10);
    return 0;
}

static void extract_json_string(const char *json, const char *key, char *out, size_t size) {
    char pattern[64];
    const char *p = NULL;
    const char *end = NULL;
    size_t len = 0;

    if (out == NULL || size == 0) {
        return;
    }
    out[0] = '\0';
    if (json == NULL || key == NULL) {
        return;
    }
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (p == NULL) {
        return;
    }
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t') {
        p++;
    }
    if (*p != '"') {
        return;
    }
    p++;
    end = strchr(p, '"');
    if (end == NULL) {
        return;
    }
    len = (size_t)(end - p);
    if (len >= size) {
        len = size - 1;
    }
    memcpy(out, p, len);
    out[len] = '\0';
}

int rules_client_fetch(const struct backend_config *cfg, struct agent_ruleset *out) {
    char url[384];
    const char *scheme = NULL;
    char *body = NULL;
    int status = -1;

    if (cfg == NULL || out == NULL || !cfg->enabled || cfg->device_id[0] == '\0') {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    scheme = cfg->scheme[0] != '\0' ? cfg->scheme : "https";
    /* uclient-fetch can't set headers, so the API key rides as a query param. */
    if (cfg->api_key[0] != '\0') {
        snprintf(url, sizeof(url), "%s://%s:%d/api/devices/%s/ruleset?apiKey=%s",
                 scheme, cfg->host, cfg->port, cfg->device_id, cfg->api_key);
    } else {
        snprintf(url, sizeof(url), "%s://%s:%d/api/devices/%s/ruleset",
                 scheme, cfg->host, cfg->port, cfg->device_id);
    }

    body = malloc(RULESET_RESP_MAX);
    if (body == NULL) {
        return -1;
    }
    body[0] = '\0';

    status = http_get(url, body, RULESET_RESP_MAX);
    if (status < 200 || status >= 300) {
        logger_info("[RULES] ruleset fetch failed (status=%d)", status);
        free(body);
        return -1;
    }

    extract_json_number(body, "udpPacketThreshold", &out->udp_packet_threshold);
    extract_json_number(body, "tcpPacketThreshold", &out->tcp_packet_threshold);
    extract_json_number(body, "byteThreshold", &out->byte_threshold);
    extract_json_string(body, "version", out->version, sizeof(out->version));

    out->loaded = 1;
    logger_info("[RULES] ruleset %s applied: udp=%llu tcp=%llu bytes=%llu",
                out->version[0] ? out->version : "(none)",
                (unsigned long long)out->udp_packet_threshold,
                (unsigned long long)out->tcp_packet_threshold,
                (unsigned long long)out->byte_threshold);

    free(body);
    return 0;
}

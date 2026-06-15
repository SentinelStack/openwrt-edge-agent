#include "backend_client.h"

#include "http_client.h"
#include "iso_time.h"
#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define JSON_BODY_MAX 1024
#define RESP_BODY_MAX 2048
#define DEFAULT_DEVICE_ID_FILE "/etc/openwrt-agent.id"

static int http_ok(int status) {
    return status >= 200 && status < 300;
}


static int read_device_id_file(const char *path, char *out, size_t size) {
    FILE *fp = NULL;
    size_t len = 0;

    if (path == NULL || path[0] == '\0' || out == NULL || size == 0) {
        return -1;
    }

    fp = fopen(path, "r");
    if (fp == NULL) {
        return -1;
    }
    if (fgets(out, (int)size, fp) == NULL) {
        fclose(fp);
        out[0] = '\0';
        return -1;
    }
    fclose(fp);

    
    len = strlen(out);
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r' ||
                       out[len - 1] == ' ' || out[len - 1] == '\t')) {
        out[--len] = '\0';
    }

    return out[0] != '\0' ? 0 : -1;
}


static void write_device_id_file(const char *path, const char *id) {
    FILE *fp = NULL;

    if (path == NULL || path[0] == '\0' || id == NULL || id[0] == '\0') {
        return;
    }

    fp = fopen(path, "w");
    if (fp == NULL) {
        logger_info("[BACKEND] could not persist deviceId to %s", path);
        return;
    }
    fprintf(fp, "%s\n", id);
    fclose(fp);
}

static void copy_env(const char *name, char *dst, size_t size, const char *fallback) {
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        value = fallback;
    }
    if (value == NULL) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, value, size - 1);
    dst[size - 1] = '\0';
}


static void json_escape(const char *in, char *out, size_t size) {
    size_t o = 0;
    size_t i;

    if (size == 0) {
        return;
    }
    if (in == NULL) {
        out[0] = '\0';
        return;
    }

    for (i = 0; in[i] != '\0' && o + 2 < size; i++) {
        char c = in[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = c;
        } else if (c == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
        } else if ((unsigned char)c < 0x20) {
            if (o + 6 < size) {
                snprintf(out + o, 7, "\\u%04x", (unsigned char)c);
                o += 6;
            }
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}


static int extract_json_string(const char *json, const char *key, char *out, size_t size) {
    char pattern[64];
    const char *p = NULL;
    const char *start = NULL;
    const char *end = NULL;
    size_t len = 0;

    if (json == NULL || size == 0) {
        return -1;
    }

    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    p = strstr(json, pattern);
    if (p == NULL) {
        return -1;
    }
    p += strlen(pattern);
    while (*p == ' ' || *p == ':') {
        p++;
    }
    if (*p != '"') {
        return -1;
    }
    start = p + 1;
    end = strchr(start, '"');
    if (end == NULL) {
        return -1;
    }

    len = (size_t)(end - start);
    if (len >= size) {
        len = size - 1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

int backend_config_load(struct backend_config *cfg) {
    const char *host = NULL;
    const char *port = NULL;

    if (cfg == NULL) {
        return 0;
    }
    memset(cfg, 0, sizeof(*cfg));

    host = getenv("BACKEND_HOST");
    if (host == NULL || host[0] == '\0') {
        cfg->enabled = 0;
        return 0;
    }
    strncpy(cfg->host, host, sizeof(cfg->host) - 1);

    /* Transport for the ruleset pull: https by default (cloud forces TLS). */
    copy_env("BACKEND_SCHEME", cfg->scheme, sizeof(cfg->scheme), "https");

    port = getenv("BACKEND_PORT");
    if (port != NULL && port[0] != '\0') {
        cfg->port = atoi(port);
    } else {
        cfg->port = (strcmp(cfg->scheme, "https") == 0) ? 443 : 8080;
    }
    if (cfg->port <= 0) {
        cfg->port = (strcmp(cfg->scheme, "https") == 0) ? 443 : 8080;
    }

    copy_env("DEVICE_ID", cfg->device_id, sizeof(cfg->device_id), "");
    copy_env("DEVICE_ID_FILE", cfg->device_id_path, sizeof(cfg->device_id_path), DEFAULT_DEVICE_ID_FILE);
    copy_env("DEVICE_NAME", cfg->device_name, sizeof(cfg->device_name), "OpenWrt Edge Agent");
    copy_env("DEVICE_IP", cfg->device_ip, sizeof(cfg->device_ip), "192.168.1.1");
    copy_env("DEVICE_FIRMWARE", cfg->firmware, sizeof(cfg->firmware), "OpenWrt 23.05.3");
    copy_env("DEVICE_MODEL", cfg->model, sizeof(cfg->model), "Linksys WRT3200ACM");
    copy_env("AGENT_API_KEY", cfg->api_key, sizeof(cfg->api_key), "edge-agent-7f3c1a9e5b2d4f80");

    
    if (cfg->device_id[0] == '\0') {
        char persisted[64];
        if (read_device_id_file(cfg->device_id_path, persisted, sizeof(persisted)) == 0) {
            strncpy(cfg->device_id, persisted, sizeof(cfg->device_id) - 1);
            cfg->device_id[sizeof(cfg->device_id) - 1] = '\0';
            logger_info("[BACKEND] reusing persisted deviceId=%s", cfg->device_id);
        }
    }

    cfg->enabled = 1;
    return 1;
}

int backend_register(struct backend_config *cfg) {
    char name_esc[128];
    char fw_esc[128];
    char model_esc[128];
    char body[JSON_BODY_MAX];
    char resp[RESP_BODY_MAX];
    char device_id[64];
    int status = 0;

    if (cfg == NULL || !cfg->enabled) {
        return -1;
    }

    json_escape(cfg->device_name, name_esc, sizeof(name_esc));
    json_escape(cfg->firmware, fw_esc, sizeof(fw_esc));
    json_escape(cfg->model, model_esc, sizeof(model_esc));

    if (cfg->device_id[0] != '\0') {
        snprintf(body, sizeof(body),
                 "{\"deviceId\":\"%s\",\"name\":\"%s\",\"ipAddress\":\"%s\","
                 "\"firmwareVersion\":\"%s\",\"model\":\"%s\"}",
                 cfg->device_id, name_esc, cfg->device_ip, fw_esc, model_esc);
    } else {
        snprintf(body, sizeof(body),
                 "{\"name\":\"%s\",\"ipAddress\":\"%s\","
                 "\"firmwareVersion\":\"%s\",\"model\":\"%s\"}",
                 name_esc, cfg->device_ip, fw_esc, model_esc);
    }

    status = http_post_json(cfg->scheme, cfg->host, cfg->port, "/api/devices/register", body, cfg->api_key, resp, sizeof(resp));
    if (!http_ok(status)) {
        logger_info("[BACKEND] device registration failed (status=%d)", status);
        return -1;
    }

    if (extract_json_string(resp, "deviceId", device_id, sizeof(device_id)) == 0) {
        strncpy(cfg->device_id, device_id, sizeof(cfg->device_id) - 1);
        cfg->device_id[sizeof(cfg->device_id) - 1] = '\0';
    }

    if (cfg->device_id[0] == '\0') {
        logger_info("[BACKEND] registration response missing deviceId");
        return -1;
    }

    write_device_id_file(cfg->device_id_path, cfg->device_id);

    logger_info("[BACKEND] device registered deviceId=%s", cfg->device_id);
    return 0;
}

/* CPU utilisation since the previous call, from /proc/stat (0-100, -1 on error). */
static int read_cpu_percent(void) {
    static unsigned long long prev_total = 0;
    static unsigned long long prev_idle = 0;
    FILE *fp = NULL;
    char label[16];
    unsigned long long user = 0, nice = 0, sys = 0, idle = 0, iowait = 0;
    unsigned long long irq = 0, softirq = 0, steal = 0;
    unsigned long long total, idle_all, dt, di;
    int pct;

    fp = fopen("/proc/stat", "r");
    if (fp == NULL) {
        return -1;
    }
    if (fscanf(fp, "%15s %llu %llu %llu %llu %llu %llu %llu %llu",
               label, &user, &nice, &sys, &idle, &iowait, &irq, &softirq, &steal) < 5) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    idle_all = idle + iowait;
    total = user + nice + sys + idle + iowait + irq + softirq + steal;
    if (prev_total == 0 || total <= prev_total) {
        dt = total;       /* first sample -> cumulative average since boot */
        di = idle_all;
    } else {
        dt = total - prev_total;
        di = idle_all - prev_idle;
    }
    prev_total = total;
    prev_idle = idle_all;
    if (dt == 0) {
        return -1;
    }
    pct = (int)(100 - (di * 100) / dt);
    if (pct < 0) {
        pct = 0;
    }
    if (pct > 100) {
        pct = 100;
    }
    return pct;
}

/* Used memory percentage from /proc/meminfo (0-100, -1 on error). */
static int read_mem_percent(void) {
    FILE *fp = NULL;
    char line[128];
    unsigned long long total = 0, avail = 0, v;

    fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "MemTotal: %llu kB", &v) == 1) {
            total = v;
        } else if (sscanf(line, "MemAvailable: %llu kB", &v) == 1) {
            avail = v;
            break;
        }
    }
    fclose(fp);
    if (total == 0) {
        return -1;
    }
    if (avail > total) {
        avail = total;
    }
    return (int)(100 - (avail * 100) / total);
}

int backend_send_heartbeat(const struct backend_config *cfg) {
    char path[128];
    char body[128];
    char timestamp[32];
    int status = 0;
    int cpu, mem;

    if (cfg == NULL || !cfg->enabled || cfg->device_id[0] == '\0') {
        return -1;
    }

    iso_time_format(time(NULL), timestamp, sizeof(timestamp));
    cpu = read_cpu_percent();
    mem = read_mem_percent();
    if (cpu >= 0 && mem >= 0) {
        snprintf(body, sizeof(body),
                 "{\"seenAt\":\"%s\",\"cpuPercent\":%d,\"memPercent\":%d}", timestamp, cpu, mem);
    } else {
        snprintf(body, sizeof(body), "{\"seenAt\":\"%s\"}", timestamp);
    }
    snprintf(path, sizeof(path), "/api/devices/%s/heartbeat", cfg->device_id);
    status = http_post_json(cfg->scheme, cfg->host, cfg->port, path, body, cfg->api_key, NULL, 0);
    return http_ok(status) ? 0 : -1;
}

int backend_send_traffic(const struct backend_config *cfg,
                         const struct traffic_stats *stats,
                         int window_seconds, const char *timestamp) {
    char body[JSON_BODY_MAX];
    int status = 0;

    if (cfg == NULL || !cfg->enabled || stats == NULL || timestamp == NULL ||
        cfg->device_id[0] == '\0') {
        return -1;
    }

    snprintf(body, sizeof(body),
             "{\"deviceId\":\"%s\",\"timestamp\":\"%s\","
             "\"totalPackets\":%llu,\"tcpPackets\":%llu,\"udpPackets\":%llu,"
             "\"totalBytes\":%llu,\"tcpBytes\":%llu,\"udpBytes\":%llu,"
             "\"windowSeconds\":%d}",
             cfg->device_id, timestamp,
             (unsigned long long)stats->total_packets,
             (unsigned long long)stats->tcp_packets,
             (unsigned long long)stats->udp_packets,
             (unsigned long long)stats->total_bytes,
             (unsigned long long)stats->tcp_bytes,
             (unsigned long long)stats->udp_bytes,
             window_seconds);

    status = http_post_json(cfg->scheme, cfg->host, cfg->port, "/api/traffic/stats", body, cfg->api_key, NULL, 0);
    return http_ok(status) ? 0 : -1;
}

int backend_send_alert(const struct backend_config *cfg,
                       const struct anomaly_alert *alert,
                       const struct flow_entry *flow,
                       int window_seconds, const char *timestamp) {
    char body[JSON_BODY_MAX];
    char desc_esc[256];
    const char *src_ip = "0.0.0.0";
    const char *dst_ip = "0.0.0.0";
    unsigned int src_port = 0;
    unsigned int dst_port = 0;
    int status = 0;

    if (cfg == NULL || !cfg->enabled || alert == NULL || timestamp == NULL ||
        cfg->device_id[0] == '\0') {
        return -1;
    }

    if (flow != NULL) {
        src_ip = flow->src_ip;
        dst_ip = flow->dst_ip;
        src_port = flow->src_port;
        dst_port = flow->dst_port;
    }

    json_escape(alert->description, desc_esc, sizeof(desc_esc));

    snprintf(body, sizeof(body),
             "{\"deviceId\":\"%s\",\"timestamp\":\"%s\",\"type\":\"%s\","
             "\"severity\":\"%s\",\"protocol\":\"%s\","
             "\"sourceIp\":\"%s\",\"destinationIp\":\"%s\","
             "\"sourcePort\":%u,\"destinationPort\":%u,"
             "\"packetCount\":%llu,\"bytesCount\":%llu,"
             "\"windowSeconds\":%d,\"description\":\"%s\"}",
             cfg->device_id, timestamp, alert->type, alert->severity, alert->protocol,
             src_ip, dst_ip, src_port, dst_port,
             (unsigned long long)alert->packet_count,
             (unsigned long long)alert->bytes_count,
             window_seconds, desc_esc);

    status = http_post_json(cfg->scheme, cfg->host, cfg->port, "/api/alerts", body, cfg->api_key, NULL, 0);
    return http_ok(status) ? 0 : -1;
}

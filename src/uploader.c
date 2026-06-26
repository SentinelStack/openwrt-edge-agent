#include "uploader.h"

#include "logger.h"
#include "rules_client.h"

#include <pthread.h>

#define UPLOAD_QUEUE_CAPACITY 4

static const struct backend_config *g_backend = NULL;

static struct upload_job g_queue[UPLOAD_QUEUE_CAPACITY];
static size_t g_head;
static size_t g_count;
static unsigned long g_dropped;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static pthread_t g_thread;
static int g_running;
static int g_started;

static int backend_ready(void) {
    return g_backend != NULL && g_backend->enabled && g_backend->device_id[0] != '\0';
}

static void run_job(const struct upload_job *job) {
    int i;

    if (!backend_ready()) {
        return;
    }

    backend_send_traffic(g_backend, &job->stats, job->window_seconds, job->timestamp);

    for (i = 0; i < job->alert_count; i++) {
        backend_send_alert(g_backend, &job->alerts[i],
                           job->alert_has_flow[i] ? &job->alert_flow[i] : NULL,
                           job->window_seconds, job->timestamp);
    }

    if (job->dns_count > 0) {
        backend_send_dns(g_backend, job->dns_events, job->dns_count,
                         job->window_seconds, job->timestamp);
    }

    if (job->send_heartbeat) {
        backend_send_heartbeat(g_backend);
    }

    if (job->sync_ruleset) {
        struct agent_ruleset ruleset;
        if (rules_client_fetch(g_backend, &ruleset) == 0) {
            anomaly_detector_set_thresholds(ruleset.udp_packet_threshold,
                                            ruleset.tcp_packet_threshold,
                                            ruleset.byte_threshold);
        }
    }
}

static void *uploader_main(void *arg) {
    struct upload_job job;
    (void)arg;

    for (;;) {
        pthread_mutex_lock(&g_lock);
        while (g_running && g_count == 0) {
            pthread_cond_wait(&g_cond, &g_lock);
        }
        if (!g_running) {
            pthread_mutex_unlock(&g_lock);
            break;
        }
        job = g_queue[g_head];
        g_head = (g_head + 1) % UPLOAD_QUEUE_CAPACITY;
        g_count--;
        pthread_mutex_unlock(&g_lock);

        run_job(&job);
    }

    return NULL;
}

int uploader_start(const struct backend_config *backend) {
    g_backend = backend;
    g_running = 1;
    if (pthread_create(&g_thread, NULL, uploader_main, NULL) != 0) {
        g_running = 0;
        return -1;
    }
    g_started = 1;
    return 0;
}

void uploader_submit(const struct upload_job *job) {
    size_t tail;

    if (job == NULL) {
        return;
    }

    pthread_mutex_lock(&g_lock);
    if (!g_started) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    if (g_count == UPLOAD_QUEUE_CAPACITY) {
        g_head = (g_head + 1) % UPLOAD_QUEUE_CAPACITY;
        g_count--;
        g_dropped++;
        if ((g_dropped % 32) == 1) {
            logger_info("uploader queue full; dropped %lu telemetry batches (backend slow/unreachable)",
                        g_dropped);
        }
    }

    tail = (g_head + g_count) % UPLOAD_QUEUE_CAPACITY;
    g_queue[tail] = *job;
    g_count++;
    pthread_cond_signal(&g_cond);
    pthread_mutex_unlock(&g_lock);
}

void uploader_stop(void) {
    if (!g_started) {
        return;
    }
    pthread_mutex_lock(&g_lock);
    g_running = 0;
    pthread_cond_signal(&g_cond);
    pthread_mutex_unlock(&g_lock);
    pthread_join(g_thread, NULL);
    g_started = 0;
}

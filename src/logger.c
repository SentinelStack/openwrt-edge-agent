#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

static void log_prefix(const char *prefix, const char *fmt, va_list args) {
    printf("%s ", prefix);
    vprintf(fmt, args);
    printf("\n");
    fflush(stdout);
}

void logger_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_prefix("[INFO]", fmt, args);
    va_end(args);
}

void logger_alert(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_prefix("[ALERT]", fmt, args);
    va_end(args);
}

void logger_packet(const char *proto, const char *src_ip, unsigned int src_port,
                   const char *dst_ip, unsigned int dst_port, unsigned int packet_size) {
    printf("[%s] %s:%u -> %s:%u size=%u\n", proto, src_ip, src_port, dst_ip, dst_port, packet_size);
    fflush(stdout);
}

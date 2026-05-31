#include "iso_time.h"

const char *iso_time_format(time_t epoch, char *buf, size_t size) {
    struct tm tm_utc;

    if (buf == NULL || size == 0) {
        return buf;
    }

    if (gmtime_r(&epoch, &tm_utc) == NULL) {
        buf[0] = '\0';
        return buf;
    }

    if (strftime(buf, size, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0) {
        buf[0] = '\0';
    }

    return buf;
}

#ifndef ISO_TIME_H
#define ISO_TIME_H

#include <stddef.h>
#include <time.h>


const char *iso_time_format(time_t epoch, char *buf, size_t size);

#endif

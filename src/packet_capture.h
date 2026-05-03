#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <stddef.h>
#include <sys/types.h>

int packet_capture_open(void);
ssize_t packet_capture_receive(int fd, unsigned char *buffer, size_t buffer_size);
void packet_capture_close(int fd);

#endif

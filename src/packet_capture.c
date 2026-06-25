#include "packet_capture.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <unistd.h>

int packet_capture_open(void) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd >= 0) {
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    }
    return fd;
}

ssize_t packet_capture_receive(int fd, unsigned char *buffer, size_t buffer_size) {
    return recvfrom(fd, buffer, buffer_size, 0, NULL, NULL);
}

void packet_capture_close(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}

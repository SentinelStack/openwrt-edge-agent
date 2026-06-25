#include "packet_capture.h"

#include "logger.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void bind_to_iface(int fd, const char *iface) {
    struct sockaddr_ll addr;
    unsigned int idx = if_nametoindex(iface);

    if (idx == 0) {
        logger_info("capture interface '%s' not found; capturing on all interfaces", iface);
        return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = (int)idx;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        logger_info("failed to bind capture to '%s'; capturing on all interfaces", iface);
        return;
    }

    logger_info("capture bound to interface '%s'", iface);
}

int packet_capture_open(void) {
    const char *iface = getenv("AGENT_CAPTURE_IFACE");
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd >= 0) {
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        if (iface != NULL && iface[0] != '\0') {
            bind_to_iface(fd, iface);
        }
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

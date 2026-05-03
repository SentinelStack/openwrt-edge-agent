#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

static uint16_t read_u16_be(const unsigned char *p) {
    uint16_t v = 0;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <tcp|udp>\n", prog);
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s tcp\n", prog);
    fprintf(stderr, "  %s udp\n", prog);
}

int main(int argc, char *argv[]) {
    int want_protocol = -1;
    int raw_sock = -1;
    unsigned char buffer[BUFFER_SIZE];

    if (argc != 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "tcp") == 0) {
        want_protocol = IPPROTO_TCP;
    } else if (strcmp(argv[1], "udp") == 0) {
        want_protocol = IPPROTO_UDP;
    } else {
        fprintf(stderr, "Invalid protocol: %s\n", argv[1]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sock < 0) {
        perror("socket(AF_PACKET, SOCK_RAW)");
        return EXIT_FAILURE;
    }

    while (1) {
        ssize_t len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom");
            close(raw_sock);
            return EXIT_FAILURE;
        }

        if ((size_t)len < sizeof(struct ethhdr)) {
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            continue;
        }

        if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        if (ip->version != 4) {
            continue;
        }

        if (ip->protocol != want_protocol) {
            continue;
        }

        size_t ip_header_len = (size_t)ip->ihl * 4;
        if (ip_header_len < sizeof(struct iphdr)) {
            continue;
        }

        size_t transport_offset = sizeof(struct ethhdr) + ip_header_len;
        if ((size_t)len < transport_offset + 4) {
            continue;
        }

        const unsigned char *transport = buffer + transport_offset;
        uint16_t src_port = read_u16_be(transport);
        uint16_t dst_port = read_u16_be(transport + 2);

        struct in_addr src_addr;
        struct in_addr dst_addr;
        src_addr.s_addr = ip->saddr;
        dst_addr.s_addr = ip->daddr;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip)) == NULL) {
            strncpy(src_ip, "unknown", sizeof(src_ip));
            src_ip[sizeof(src_ip) - 1] = '\0';
        }
        if (inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip)) == NULL) {
            strncpy(dst_ip, "unknown", sizeof(dst_ip));
            dst_ip[sizeof(dst_ip) - 1] = '\0';
        }

        if (want_protocol == IPPROTO_TCP) {
            printf("[TCP] %s:%u -> %s:%u\n", src_ip, src_port, dst_ip, dst_port);
        } else {
            printf("[UDP] %s:%u -> %s:%u\n", src_ip, src_port, dst_ip, dst_port);
        }
        fflush(stdout);
    }

    close(raw_sock);
    return EXIT_SUCCESS;
}

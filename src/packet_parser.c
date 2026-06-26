#include "packet_parser.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <string.h>

static uint16_t read_u16_be(const unsigned char *p) {
    uint16_t value = 0;
    memcpy(&value, p, sizeof(value));
    return ntohs(value);
}

int parse_packet(const unsigned char *buffer, size_t len, struct parsed_packet *out) {
    const struct ethhdr *eth = NULL;
    const struct iphdr *ip = NULL;
    size_t ip_header_len = 0;
    size_t transport_offset = 0;
    struct in_addr src_addr;
    struct in_addr dst_addr;

    if (buffer == NULL || out == NULL) {
        return 0;
    }

    if (len < sizeof(struct ethhdr)) {
        return 0;
    }

    eth = (const struct ethhdr *)buffer;
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return 0;
    }

    if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return 0;
    }

    ip = (const struct iphdr *)(buffer + sizeof(struct ethhdr));
    if (ip->version != 4) {
        return 0;
    }

    ip_header_len = (size_t)ip->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr)) {
        return 0;
    }

    transport_offset = sizeof(struct ethhdr) + ip_header_len;
    if (len < transport_offset + 4) {
        return 0;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->protocol = ip->protocol;
    out->src_port = read_u16_be(buffer + transport_offset);
    out->dst_port = read_u16_be(buffer + transport_offset + 2);
    out->packet_size = len;

    if (ip->protocol == IPPROTO_UDP && out->dst_port == 53) {
        size_t dns_offset = transport_offset + 8;
        if (dns_offset + 12 <= len) {
            const unsigned char *dns = buffer + dns_offset;
            uint16_t qdcount = read_u16_be(dns + 4);
            if (qdcount >= 1 && (dns[2] & 0x80) == 0) {
                size_t pos = dns_offset + 12;
                size_t o = 0;
                int ok = 1;
                int done = 0;
                while (!done) {
                    unsigned char label_len;
                    size_t j;
                    if (pos >= len) {
                        ok = 0;
                        break;
                    }
                    label_len = buffer[pos];
                    if (label_len == 0) {
                        done = 1;
                        break;
                    }
                    if ((label_len & 0xC0) != 0) {
                        ok = 0;
                        break;
                    }
                    if (pos + 1 + label_len > len) {
                        ok = 0;
                        break;
                    }
                    if (o + label_len + 1 > sizeof(out->dns_qname) - 1) {
                        ok = 0;
                        break;
                    }
                    for (j = 0; j < label_len; j++) {
                        out->dns_qname[o++] = (char)buffer[pos + 1 + j];
                    }
                    out->dns_qname[o++] = '.';
                    pos += 1 + label_len;
                }
                if (ok && done && o > 0) {
                    out->dns_qname[o - 1] = '\0';
                    out->is_dns_query = 1;
                } else {
                    out->dns_qname[0] = '\0';
                    out->is_dns_query = 0;
                }
            }
        }
    }

    src_addr.s_addr = ip->saddr;
    dst_addr.s_addr = ip->daddr;
    if (inet_ntop(AF_INET, &src_addr, out->src_ip, sizeof(out->src_ip)) == NULL) {
        strncpy(out->src_ip, "unknown", sizeof(out->src_ip));
        out->src_ip[sizeof(out->src_ip) - 1] = '\0';
    }
    if (inet_ntop(AF_INET, &dst_addr, out->dst_ip, sizeof(out->dst_ip)) == NULL) {
        strncpy(out->dst_ip, "unknown", sizeof(out->dst_ip));
        out->dst_ip[sizeof(out->dst_ip) - 1] = '\0';
    }

    return 1;
}

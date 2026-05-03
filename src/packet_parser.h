#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define PROTO_TCP 6
#define PROTO_UDP 17

struct parsed_packet {
    char src_ip[16];
    char dst_ip[16];
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    size_t packet_size;
};

int parse_packet(const unsigned char *buffer, size_t len, struct parsed_packet *out);

#endif

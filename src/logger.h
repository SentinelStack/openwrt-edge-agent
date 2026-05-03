#ifndef LOGGER_H
#define LOGGER_H

void logger_info(const char *fmt, ...);
void logger_alert(const char *fmt, ...);
void logger_packet(const char *proto, const char *src_ip, unsigned int src_port,
                   const char *dst_ip, unsigned int dst_port, unsigned int packet_size);

#endif

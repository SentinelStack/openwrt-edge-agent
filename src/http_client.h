#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>


int http_post_json(const char *host, int port, const char *path,
                   const char *body, char *resp_body, size_t resp_size);

#endif

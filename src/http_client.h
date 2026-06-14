#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>


int http_post_json(const char *host, int port, const char *path,
                   const char *body, char *resp_body, size_t resp_size);

/* Plain HTTP GET. Returns the HTTP status code (>=200) or -1 on transport
   error. The response body (headers stripped) is copied into resp_body. */
int http_get(const char *host, int port, const char *path,
             char *resp_body, size_t resp_size);

#endif

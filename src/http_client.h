#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>


int http_post_json(const char *host, int port, const char *path,
                   const char *body, char *resp_body, size_t resp_size);

/* HTTP(S) GET via the system's TLS-capable client (uclient-fetch). Pass a full
   URL (http:// or https://). Returns 200 on success or -1 on failure; the
   response body is copied into resp_body. */
int http_get(const char *url, char *resp_body, size_t resp_size);

#endif

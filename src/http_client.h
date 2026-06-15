#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>


/* POST a JSON body. `scheme` is "https" (in-process mbedTLS) or "http"
   (plain socket). `api_key` (may be NULL/empty) is sent as the X-API-Key
   header. Returns the HTTP status code or -1 on transport error. */
int http_post_json(const char *scheme, const char *host, int port, const char *path,
                   const char *body, const char *api_key, char *resp_body, size_t resp_size);

/* HTTP(S) GET via the system's TLS-capable client (uclient-fetch). Pass a full
   URL (http:// or https://). Returns 200 on success or -1 on failure; the
   response body is copied into resp_body. */
int http_get(const char *url, char *resp_body, size_t resp_size);

#endif

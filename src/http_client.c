#include "http_client.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#define HTTP_TIMEOUT_SECONDS 3
#define HTTP_REQUEST_MAX 4096
#define HTTP_RESPONSE_MAX 4096
#define HTTP_GET_RESPONSE_MAX 8192
#define CA_BUNDLE_PATH "/etc/ssl/certs/ca-certificates.crt"

static int send_all(int fd, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int parse_status_code(const char *response) {
    int major = 0;
    int minor = 0;
    int code = 0;
    if (sscanf(response, "HTTP/%d.%d %d", &major, &minor, &code) != 3) {
        return -1;
    }
    (void)major;
    (void)minor;
    return code;
}

static int connect_to(const char *host, int port) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    struct timeval tv;
    char port_str[16];
    int fd = -1;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

    tv.tv_sec = HTTP_TIMEOUT_SECONDS;
    tv.tv_usec = 0;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* Build "X-API-Key: <key>\r\n" into out, or an empty string if no key. */
static void api_key_header(const char *api_key, char *out, size_t size) {
    if (api_key != NULL && api_key[0] != '\0') {
        snprintf(out, size, "X-API-Key: %s\r\n", api_key);
    } else {
        out[0] = '\0';
    }
}

static int http_post_plain(const char *host, int port, const char *path,
                           const char *body, const char *api_key,
                           char *resp_body, size_t resp_size) {
    char request[HTTP_REQUEST_MAX];
    char response[HTTP_RESPONSE_MAX];
    char key_hdr[96];
    int fd = -1;
    int request_len = 0;
    int status = -1;
    size_t total = 0;
    const char *body_start = NULL;

    if (host == NULL || path == NULL || body == NULL) {
        return -1;
    }

    if (resp_body != NULL && resp_size > 0) {
        resp_body[0] = '\0';
    }

    api_key_header(api_key, key_hdr, sizeof(key_hdr));
    request_len = snprintf(request, sizeof(request),
                           "POST %s HTTP/1.1\r\n"
                           "Host: %s:%d\r\n"
                           "Content-Type: application/json\r\n"
                           "%s"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "%s",
                           path, host, port, key_hdr, strlen(body), body);
    if (request_len < 0 || (size_t)request_len >= sizeof(request)) {
        return -1;
    }

    fd = connect_to(host, port);
    if (fd < 0) {
        return -1;
    }

    if (send_all(fd, request, (size_t)request_len) != 0) {
        close(fd);
        return -1;
    }

    while (total < sizeof(response) - 1) {
        ssize_t n = recv(fd, response + total, sizeof(response) - 1 - total, 0);
        if (n <= 0) {
            break; 
        }
        total += (size_t)n;
    }
    close(fd);

    if (total == 0) {
        return -1;
    }
    response[total] = '\0';

    status = parse_status_code(response);

    if (resp_body != NULL && resp_size > 0) {
        body_start = strstr(response, "\r\n\r\n");
        if (body_start != NULL) {
            body_start += 4;
            strncpy(resp_body, body_start, resp_size - 1);
            resp_body[resp_size - 1] = '\0';
        }
    }

    return status;
}

/* In-process HTTPS POST via mbedTLS — gives the agent a real TLS client so it
   can register and upload telemetry directly to the cloud backend. */
static int http_post_tls(const char *host, int port, const char *path,
                         const char *body, const char *api_key,
                         char *resp_body, size_t resp_size) {
    char request[HTTP_REQUEST_MAX];
    char response[HTTP_RESPONSE_MAX];
    char port_str[8];
    char key_hdr[96];
    int request_len = 0;
    int status = -1;
    int ret = 0;
    int ca_ok = -1;
    size_t total = 0;
    size_t written = 0;
    const char *body_start = NULL;

    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt cacert;

    if (host == NULL || path == NULL || body == NULL) {
        return -1;
    }
    if (resp_body != NULL && resp_size > 0) {
        resp_body[0] = '\0';
    }

    api_key_header(api_key, key_hdr, sizeof(key_hdr));
    request_len = snprintf(request, sizeof(request),
                           "POST %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Content-Type: application/json\r\n"
                           "%s"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "%s",
                           path, host, key_hdr, strlen(body), body);
    if (request_len < 0 || (size_t)request_len >= sizeof(request)) {
        return -1;
    }

    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        goto cleanup;
    }

    /* Verify the server cert against the system CA bundle when present. */
    ca_ok = mbedtls_x509_crt_parse_file(&cacert, CA_BUNDLE_PATH);

    snprintf(port_str, sizeof(port_str), "%d", port);
    if (mbedtls_net_connect(&net, host, port_str, MBEDTLS_NET_PROTO_TCP) != 0) {
        goto cleanup;
    }
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto cleanup;
    }
    mbedtls_ssl_conf_authmode(&conf,
                              ca_ok == 0 ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if (mbedtls_ssl_setup(&ssl, &conf) != 0) {
        goto cleanup;
    }
    if (mbedtls_ssl_set_hostname(&ssl, host) != 0) {
        goto cleanup;
    }
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            goto cleanup;
        }
    }

    while (written < (size_t)request_len) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char *)request + written,
                                (size_t)request_len - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret <= 0) {
            goto cleanup;
        }
        written += (size_t)ret;
    }

    while (total < sizeof(response) - 1) {
        ret = mbedtls_ssl_read(&ssl, (unsigned char *)response + total,
                               sizeof(response) - 1 - total);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret <= 0) {
            break; /* close_notify, EOF or error */
        }
        total += (size_t)ret;
    }
    response[total] = '\0';

    if (total > 0) {
        status = parse_status_code(response);
        if (resp_body != NULL && resp_size > 0) {
            body_start = strstr(response, "\r\n\r\n");
            if (body_start != NULL) {
                body_start += 4;
                strncpy(resp_body, body_start, resp_size - 1);
                resp_body[resp_size - 1] = '\0';
            }
        }
    }

    mbedtls_ssl_close_notify(&ssl);

cleanup:
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&net);
    return status;
}

int http_post_json(const char *scheme, const char *host, int port, const char *path,
                   const char *body, const char *api_key, char *resp_body, size_t resp_size) {
    if (scheme != NULL && strcmp(scheme, "https") == 0) {
        return http_post_tls(host, port, path, body, api_key, resp_body, resp_size);
    }
    return http_post_plain(host, port, path, body, api_key, resp_body, resp_size);
}

/* Only these characters are allowed in a URL passed to the shell via popen,
   so a crafted device id / host can't inject commands. */
static int url_is_safe(const char *url) {
    const char *p;
    for (p = url; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || strchr(":/._-~?=&%", c) != NULL;
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

int http_get(const char *url, char *resp_body, size_t resp_size) {
    char cmd[512];
    FILE *fp = NULL;
    size_t total = 0;
    int rc = -1;

    if (url == NULL || !url_is_safe(url)) {
        return -1;
    }
    if (resp_body != NULL && resp_size > 0) {
        resp_body[0] = '\0';
    }

    /* uclient-fetch carries the OpenWrt TLS stack (libustream-mbedtls), so this
       does a real, cert-validated HTTPS GET — what the raw socket couldn't. */
    if (snprintf(cmd, sizeof(cmd),
                 "uclient-fetch -q -O - --timeout=5 \"%s\" 2>/dev/null", url) >= (int)sizeof(cmd)) {
        return -1;
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        return -1;
    }

    if (resp_body != NULL && resp_size > 0) {
        while (total < resp_size - 1) {
            size_t n = fread(resp_body + total, 1, resp_size - 1 - total, fp);
            if (n == 0) {
                break;
            }
            total += n;
        }
        resp_body[total] = '\0';
    } else {
        char drain[256];
        while (fread(drain, 1, sizeof(drain), fp) > 0) {
            /* discard */
        }
    }

    rc = pclose(fp);
    if (rc == -1 || !WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        return -1;
    }
    return 200;
}

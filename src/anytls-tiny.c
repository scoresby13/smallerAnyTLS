/*
 * smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client
 *
 * Designed for embedded Linux / OpenWrt routers with severe storage constraints.
 * Binary footprint: ~15 KB.
 * Dependencies: libc, libdl (dynamically loads OpenSSL from firmware ROM).
 *
 * Supports:
 *  - AnyTLS v2 multiplexed TLS tunnel
 *  - SOCKS5 proxy server
 *  - Transparent TCP redirection (SO_ORIGINAL_DST)
 *  - Anti-poisoning UDP-to-TCP DNS forwarder
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <linux/netfilter_ipv4.h>

#define CMD_WASTE               0
#define CMD_SYN                 1
#define CMD_PSH                 2
#define CMD_FIN                 3
#define CMD_SETTINGS            4
#define CMD_ALERT               5
#define CMD_UPDATE_PADDING      6
#define CMD_SYNACK              7
#define CMD_HEART_REQ           8
#define CMD_HEART_RESP          9
#define CMD_SERVER_SETTINGS    10

#define MAX_STREAMS 128
#define MAX_DNS_REQS 64
#define RX_STREAM_BUF_SIZE (128 * 1024)

#ifndef SO_ORIGINAL_DST
#define SO_ORIGINAL_DST 80
#endif

/* Dynamic OpenSSL function pointers */
typedef void SSL_CTX;
typedef void SSL;
typedef void SSL_METHOD;

static const SSL_METHOD* (*p_TLS_client_method)(void);
static SSL_CTX* (*p_SSL_CTX_new)(const SSL_METHOD*);
static void (*p_SSL_CTX_set_verify)(SSL_CTX*, int, void*);
static SSL* (*p_SSL_new)(SSL_CTX*);
static int (*p_SSL_set_fd)(SSL*, int);
static long (*p_SSL_ctrl)(SSL*, int, long, void*);
static int (*p_SSL_set_alpn_protos)(SSL*, const unsigned char*, unsigned int);
static int (*p_SSL_connect)(SSL*);
static int (*p_SSL_read)(SSL*, void*, int);
static int (*p_SSL_write)(SSL*, const void*, int);
static int (*p_SSL_get_error)(const SSL*, int);
static int (*p_SSL_shutdown)(SSL*);
static void (*p_SSL_free)(SSL*);
static int (*p_SSL_pending)(const SSL*);
static unsigned char* (*p_SHA256)(const unsigned char*, size_t, unsigned char*);

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name 0
#define SSL_VERIFY_NONE 0
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3

static int init_openssl(void) {
    const char *ssl_libs[] = {
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
        "libssl.so.3",
        "libssl.so.1.1",
        "libssl.so",
        NULL
    };
    const char *crypto_libs[] = {
        "/usr/lib/libcrypto.so.3",
        "/usr/lib/libcrypto.so.1.1",
        "libcrypto.so.3",
        "libcrypto.so.1.1",
        "libcrypto.so",
        NULL
    };

    void *h_ssl = NULL;
    for (int i = 0; ssl_libs[i]; i++) {
        h_ssl = dlopen(ssl_libs[i], RTLD_NOW | RTLD_GLOBAL);
        if (h_ssl) break;
    }

    void *h_crypto = NULL;
    for (int i = 0; crypto_libs[i]; i++) {
        h_crypto = dlopen(crypto_libs[i], RTLD_NOW | RTLD_GLOBAL);
        if (h_crypto) break;
    }

    if (!h_ssl || !h_crypto) {
        fprintf(stderr, "[anytls-tiny] Error: OpenSSL shared libraries (libssl / libcrypto) not found.\n");
        return -1;
    }

    p_TLS_client_method = dlsym(h_ssl, "TLS_client_method");
    p_SSL_CTX_new = dlsym(h_ssl, "SSL_CTX_new");
    p_SSL_CTX_set_verify = dlsym(h_ssl, "SSL_CTX_set_verify");
    p_SSL_new = dlsym(h_ssl, "SSL_new");
    p_SSL_set_fd = dlsym(h_ssl, "SSL_set_fd");
    p_SSL_ctrl = dlsym(h_ssl, "SSL_ctrl");
    p_SSL_set_alpn_protos = dlsym(h_ssl, "SSL_set_alpn_protos");
    p_SSL_connect = dlsym(h_ssl, "SSL_connect");
    p_SSL_read = dlsym(h_ssl, "SSL_read");
    p_SSL_write = dlsym(h_ssl, "SSL_write");
    p_SSL_get_error = dlsym(h_ssl, "SSL_get_error");
    p_SSL_shutdown = dlsym(h_ssl, "SSL_shutdown");
    p_SSL_free = dlsym(h_ssl, "SSL_free");
    p_SSL_pending = dlsym(h_ssl, "SSL_pending");
    p_SHA256 = dlsym(h_crypto, "SHA256");

    if (!p_TLS_client_method || !p_SSL_CTX_new || !p_SSL_new || !p_SSL_connect || !p_SHA256) {
        fprintf(stderr, "[anytls-tiny] Error: Failed to resolve required OpenSSL symbols: %s\n", dlerror());
        return -1;
    }
    return 0;
}

/* Stream tracking */
typedef struct {
    uint32_t stream_id;
    int client_fd;
    int is_redir;
    int socks_state; /* 0: auth, 1: req, 2: connected */
} stream_t;

typedef struct {
    uint32_t stream_id;
    struct sockaddr_in client_addr;
    time_t expire;
    int in_use;
} dns_req_t;

static stream_t  g_streams[MAX_STREAMS];
static dns_req_t g_dns_reqs[MAX_DNS_REQS];
static uint32_t  g_stream_counter = 1;

static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl = NULL;
static int      g_ssl_fd = -1;

/* Static BSS buffers */
static uint8_t g_rx_buf[RX_STREAM_BUF_SIZE];
static int     g_rx_len = 0;
static uint8_t g_tx_buf[65536 + 16];
static uint8_t g_client_rx_buf[16384];

static char g_server_host[256] = "";
static int  g_server_port = 443;
static char g_password[256] = "";
static char g_sni[256] = "";
static int  g_socks_port = 1080;
static int  g_redir_port = 1100;
static int  g_dns_port = 5353;
static int  g_dns_fd = -1;

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_nodelay(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static stream_t *find_stream_by_id(uint32_t sid) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0 && g_streams[i].stream_id == sid)
            return &g_streams[i];
    }
    return NULL;
}

static stream_t *alloc_stream(int client_fd, int is_redir) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd <= 0) {
            g_streams[i].stream_id = g_stream_counter;
            g_stream_counter += 2; /* Client stream IDs are odd */
            g_streams[i].client_fd = client_fd;
            g_streams[i].is_redir = is_redir;
            g_streams[i].socks_state = is_redir ? 2 : 0;
            return &g_streams[i];
        }
    }
    return NULL;
}

static int send_frame(uint8_t cmd, uint32_t stream_id, const uint8_t *data, uint16_t len) {
    if (!g_ssl) return -1;
    if ((size_t)(7 + len) > sizeof(g_tx_buf)) return -1;

    g_tx_buf[0] = cmd;
    g_tx_buf[1] = (stream_id >> 24) & 0xFF;
    g_tx_buf[2] = (stream_id >> 16) & 0xFF;
    g_tx_buf[3] = (stream_id >> 8) & 0xFF;
    g_tx_buf[4] = stream_id & 0xFF;
    g_tx_buf[5] = (len >> 8) & 0xFF;
    g_tx_buf[6] = len & 0xFF;
    if (len > 0 && data) {
        memcpy(g_tx_buf + 7, data, len);
    }

    int total = 7 + len;
    int sent = 0;
    while (sent < total) {
        int n = p_SSL_write(g_ssl, g_tx_buf + sent, total - sent);
        if (n <= 0) {
            int err = p_SSL_get_error(g_ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                struct pollfd pfd = { .fd = g_ssl_fd, .events = (err == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN) };
                if (poll(&pfd, 1, 2000) > 0) continue;
            }
            return -1;
        }
        sent += n;
    }
    return 0;
}

static void close_stream(stream_t *st) {
    if (!st || st->client_fd <= 0) return;
    send_frame(CMD_FIN, st->stream_id, NULL, 0);
    close(st->client_fd);
    st->client_fd = -1;
    st->stream_id = 0;
}

static void close_all_streams(void) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0) {
            close(g_streams[i].client_fd);
            g_streams[i].client_fd = -1;
            g_streams[i].stream_id = 0;
        }
    }
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        g_dns_reqs[i].in_use = 0;
    }
}

static void disconnect_upstream(void) {
    if (g_ssl) {
        p_SSL_shutdown(g_ssl);
        p_SSL_free(g_ssl);
        g_ssl = NULL;
    }
    if (g_ssl_fd >= 0) {
        close(g_ssl_fd);
        g_ssl_fd = -1;
    }
    g_rx_len = 0;
    close_all_streams();
}

static int connect_upstream(void) {
    disconnect_upstream();
    printf("[anytls-tiny] Connecting to upstream %s:%d (SNI: %s)...\n", g_server_host, g_server_port, g_sni);
    fflush(stdout);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", g_server_port);

    if (getaddrinfo(g_server_host, port_str, &hints, &res) != 0 || !res) {
        fprintf(stderr, "[anytls-tiny] Failed to resolve %s\n", g_server_host);
        return -1;
    }

    g_ssl_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (g_ssl_fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
    setsockopt(g_ssl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(g_ssl_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    set_tcp_nodelay(g_ssl_fd);

    if (connect(g_ssl_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("[anytls-tiny] Connect error");
        close(g_ssl_fd);
        g_ssl_fd = -1;
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    g_ssl = p_SSL_new(g_ssl_ctx);
    p_SSL_set_fd(g_ssl, g_ssl_fd);
    p_SSL_ctrl(g_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, g_sni);

    /* ALPN: h2, http/1.1 */
    const unsigned char alpn[] = { 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    p_SSL_set_alpn_protos(g_ssl, alpn, sizeof(alpn));

    if (p_SSL_connect(g_ssl) <= 0) {
        fprintf(stderr, "[anytls-tiny] SSL_connect failed\n");
        disconnect_upstream();
        return -1;
    }

    printf("[anytls-tiny] TLS handshake successful!\n");
    fflush(stdout);

    /* 1. Auth Header: SHA256(password) + uint16(30) + 30 zero bytes */
    uint8_t auth[32 + 2 + 30];
    p_SHA256((const unsigned char *)g_password, strlen(g_password), auth);
    auth[32] = 0;
    auth[33] = 30;
    memset(auth + 34, 0, 30);

    /* 2. cmdSettings: v=2\nclient=anytls/0.0.1\npadding-md5=00000000000000000000000000000000\n */
    const char settings_data[] = "v=2\nclient=anytls/0.0.1\npadding-md5=00000000000000000000000000000000\n";
    uint16_t slen = strlen(settings_data);
    uint8_t frame[7 + slen];
    frame[0] = CMD_SETTINGS;
    memset(frame + 1, 0, 4);
    frame[5] = (slen >> 8) & 0xFF;
    frame[6] = slen & 0xFF;
    memcpy(frame + 7, settings_data, slen);

    uint8_t init_pkt[sizeof(auth) + sizeof(frame)];
    memcpy(init_pkt, auth, sizeof(auth));
    memcpy(init_pkt + sizeof(auth), frame, sizeof(frame));

    if (p_SSL_write(g_ssl, init_pkt, sizeof(init_pkt)) <= 0) {
        disconnect_upstream();
        return -1;
    }

    printf("[anytls-tiny] AnyTLS Auth + Settings sent successfully! Ready for traffic.\n");
    fflush(stdout);
    set_nonblock(g_ssl_fd);
    g_rx_len = 0;
    return 0;
}

static int create_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    set_nonblock(fd);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind tcp");
        close(fd);
        return -1;
    }
    listen(fd, 64);
    return fd;
}

static int create_udp_listener(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    set_nonblock(fd);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind udp");
        close(fd);
        return -1;
    }
    return fd;
}

static void handle_new_connection(int listen_fd, int is_redir) {
    struct sockaddr_in client_addr;
    socklen_t clen = sizeof(client_addr);
    int cfd = accept(listen_fd, (struct sockaddr *)&client_addr, &clen);
    if (cfd < 0) return;

    set_nonblock(cfd);
    set_tcp_nodelay(cfd);

    if (!g_ssl) {
        if (connect_upstream() < 0) {
            close(cfd);
            return;
        }
    }

    stream_t *st = alloc_stream(cfd, is_redir);
    if (!st) {
        close(cfd);
        return;
    }

    if (is_redir) {
        struct sockaddr_in orig_dst;
        socklen_t dlen = sizeof(orig_dst);
        if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &dlen) < 0) {
            close_stream(st);
            return;
        }

        uint8_t socks_addr[7];
        socks_addr[0] = 0x01; /* IPv4 */
        memcpy(socks_addr + 1, &orig_dst.sin_addr.s_addr, 4);
        memcpy(socks_addr + 5, &orig_dst.sin_port, 2);

        send_frame(CMD_SYN, st->stream_id, NULL, 0);
        send_frame(CMD_PSH, st->stream_id, socks_addr, 7);
    }
}

static int send_all(int fd, const uint8_t *data, size_t len) {
    size_t total = 0;
    while (total < len) {
        int n = send(fd, data + total, len - total, 0);
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT };
                if (poll(&pfd, 1, 1000) > 0) continue;
            }
            return -1;
        }
        total += n;
    }
    return 0;
}

static void handle_client_data(stream_t *st) {
    if (!st->is_redir && st->socks_state == 0) {
        int n = recv(st->client_fd, g_client_rx_buf, sizeof(g_client_rx_buf), 0);
        if (n <= 0) { close_stream(st); return; }
        if (g_client_rx_buf[0] != 0x05) { close_stream(st); return; }
        uint8_t resp[2] = { 0x05, 0x00 };
        send_all(st->client_fd, resp, 2);
        st->socks_state = 1;
        return;
    }

    if (!st->is_redir && st->socks_state == 1) {
        int n = recv(st->client_fd, g_client_rx_buf, sizeof(g_client_rx_buf), 0);
        if (n < 4) { close_stream(st); return; }
        if (g_client_rx_buf[1] != 0x01) { close_stream(st); return; }

        uint8_t *saddr = g_client_rx_buf + 3;
        int saddr_len = 0;
        if (saddr[0] == 0x01) saddr_len = 1 + 4 + 2;
        else if (saddr[0] == 0x03) saddr_len = 1 + 1 + saddr[1] + 2;
        else if (saddr[0] == 0x04) saddr_len = 1 + 16 + 2;
        else { close_stream(st); return; }

        send_frame(CMD_SYN, st->stream_id, NULL, 0);
        send_frame(CMD_PSH, st->stream_id, saddr, saddr_len);

        uint8_t resp[10] = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        send_all(st->client_fd, resp, 10);
        st->socks_state = 2;
        return;
    }

    while (1) {
        int n = recv(st->client_fd, g_client_rx_buf, sizeof(g_client_rx_buf), 0);
        if (n > 0) {
            if (send_frame(CMD_PSH, st->stream_id, g_client_rx_buf, n) < 0) {
                close_stream(st);
                disconnect_upstream();
                break;
            }
        } else if (n == 0) {
            close_stream(st);
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            close_stream(st);
            break;
        }
    }
}

static void handle_dns_udp_query(void) {
    uint8_t buf[2048];
    struct sockaddr_in cli;
    socklen_t clen = sizeof(cli);
    int n = recvfrom(g_dns_fd, buf, sizeof(buf), 0, (struct sockaddr *)&cli, &clen);
    if (n <= 12) return;

    if (!g_ssl) {
        if (connect_upstream() < 0) return;
    }

    int slot = -1;
    time_t now = time(NULL);
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (!g_dns_reqs[i].in_use || now >= g_dns_reqs[i].expire) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return;

    uint32_t sid = g_stream_counter;
    g_stream_counter += 2;

    g_dns_reqs[slot].stream_id = sid;
    memcpy(&g_dns_reqs[slot].client_addr, &cli, sizeof(cli));
    g_dns_reqs[slot].expire = now + 6;
    g_dns_reqs[slot].in_use = 1;

    /* Connect to Google Public DNS 8.8.8.8:53 */
    static const uint8_t dns_target[7] = { 0x01, 8, 8, 8, 8, 0, 53 };
    send_frame(CMD_SYN, sid, NULL, 0);
    send_frame(CMD_PSH, sid, dns_target, 7);

    /* Send query with 2-byte length prefix */
    uint8_t tcp_query[2 + 2048];
    tcp_query[0] = (n >> 8) & 0xFF;
    tcp_query[1] = n & 0xFF;
    memcpy(tcp_query + 2, buf, n);
    send_frame(CMD_PSH, sid, tcp_query, 2 + n);
}

static void handle_upstream_data(void) {
    while (1) {
        if (g_rx_len >= (int)sizeof(g_rx_buf)) {
            fprintf(stderr, "[anytls-tiny] RX buffer overflow, resetting connection\n");
            disconnect_upstream();
            return;
        }

        int space = sizeof(g_rx_buf) - g_rx_len;
        int n = p_SSL_read(g_ssl, g_rx_buf + g_rx_len, space);
        if (n <= 0) {
            int err = p_SSL_get_error(g_ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) break;
            printf("[anytls-tiny] Upstream SSL disconnected (err=%d)\n", err);
            fflush(stdout);
            disconnect_upstream();
            return;
        }
        g_rx_len += n;

        while (g_rx_len >= 7) {
            uint8_t cmd = g_rx_buf[0];
            uint32_t sid = ((uint32_t)g_rx_buf[1] << 24) |
                           ((uint32_t)g_rx_buf[2] << 16) |
                           ((uint32_t)g_rx_buf[3] << 8)  |
                           (uint32_t)g_rx_buf[4];
            uint16_t flen = ((uint16_t)g_rx_buf[5] << 8) | g_rx_buf[6];

            if (g_rx_len < 7 + flen) {
                break;
            }

            uint8_t *payload = g_rx_buf + 7;
            if (cmd == CMD_PSH) {
                int is_dns = 0;
                for (int i = 0; i < MAX_DNS_REQS; i++) {
                    if (g_dns_reqs[i].in_use && g_dns_reqs[i].stream_id == sid) {
                        is_dns = 1;
                        if (flen > 2) {
                            sendto(g_dns_fd, payload + 2, flen - 2, 0,
                                   (struct sockaddr *)&g_dns_reqs[i].client_addr,
                                   sizeof(g_dns_reqs[i].client_addr));
                        }
                        g_dns_reqs[i].in_use = 0;
                        send_frame(CMD_FIN, sid, NULL, 0);
                        break;
                    }
                }
                if (!is_dns) {
                    stream_t *st = find_stream_by_id(sid);
                    if (st && st->client_fd > 0) {
                        if (send_all(st->client_fd, payload, flen) < 0) {
                            close_stream(st);
                        }
                    }
                }
            } else if (cmd == CMD_FIN) {
                for (int i = 0; i < MAX_DNS_REQS; i++) {
                    if (g_dns_reqs[i].in_use && g_dns_reqs[i].stream_id == sid) {
                        g_dns_reqs[i].in_use = 0;
                        break;
                    }
                }
                stream_t *st = find_stream_by_id(sid);
                if (st) close_stream(st);
            } else if (cmd == CMD_HEART_REQ) {
                send_frame(CMD_HEART_RESP, 0, NULL, 0);
            }

            int remaining = g_rx_len - (7 + flen);
            if (remaining > 0) {
                memmove(g_rx_buf, g_rx_buf + 7 + flen, remaining);
            }
            g_rx_len = remaining;
        }

        if (p_SSL_pending && p_SSL_pending(g_ssl) > 0) {
            continue;
        }
        break;
    }
}

static void print_usage(const char *prog) {
    fprintf(stderr, "smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client (~15 KB)\n\n");
    fprintf(stderr, "Usage: %s -s <server> -p <port> -k <password> -h <sni> [options]\n\n", prog);
    fprintf(stderr, "Required options:\n");
    fprintf(stderr, "  -s <host/ip>    Upstream AnyTLS server address\n");
    fprintf(stderr, "  -p <port>       Upstream AnyTLS server port (e.g. 443)\n");
    fprintf(stderr, "  -k <password>   AnyTLS authentication password or UUID\n");
    fprintf(stderr, "  -h <sni>        TLS Server Name Indication (SNI, e.g. www.apple.com)\n\n");
    fprintf(stderr, "Optional:\n");
    fprintf(stderr, "  -l <port>       Local SOCKS5 proxy port (default: 1080)\n");
    fprintf(stderr, "  -r <port>       Transparent redirect port (SO_ORIGINAL_DST, default: 1100)\n");
    fprintf(stderr, "  -u <port>       DNS-over-TCP UDP listening port (default: 5353)\n");
    fprintf(stderr, "  -d              Run as background daemon\n");
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "s:p:k:h:l:r:u:d")) != -1) {
        switch (opt) {
            case 's': strncpy(g_server_host, optarg, sizeof(g_server_host)-1); break;
            case 'p': g_server_port = atoi(optarg); break;
            case 'k': strncpy(g_password, optarg, sizeof(g_password)-1); break;
            case 'h': strncpy(g_sni, optarg, sizeof(g_sni)-1); break;
            case 'l': g_socks_port = atoi(optarg); break;
            case 'r': g_redir_port = atoi(optarg); break;
            case 'u': g_dns_port = atoi(optarg); break;
            case 'd':
                if (daemon(1, 1) < 0) {
                    perror("daemon");
                    return 1;
                }
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (g_server_host[0] == '\0' || g_password[0] == '\0') {
        fprintf(stderr, "[anytls-tiny] Error: Server (-s) and password (-k) are required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (g_sni[0] == '\0') {
        strncpy(g_sni, g_server_host, sizeof(g_sni) - 1);
    }

    signal(SIGPIPE, SIG_IGN);

    if (init_openssl() < 0) {
        return 1;
    }

    g_ssl_ctx = p_SSL_CTX_new(p_TLS_client_method());
    p_SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);

    int socks_fd = create_listener(g_socks_port);
    int redir_fd = create_listener(g_redir_port);
    g_dns_fd = create_udp_listener(g_dns_port);

    if (socks_fd < 0 || redir_fd < 0 || g_dns_fd < 0) {
        fprintf(stderr, "[anytls-tiny] Failed to bind local ports (socks:%d, redir:%d, dns:%d)\n",
                g_socks_port, g_redir_port, g_dns_port);
        return 1;
    }

    printf("[anytls-tiny] Started! SOCKS5:%d, Redir:%d, DNS-UDP:%d\n", g_socks_port, g_redir_port, g_dns_port);
    fflush(stdout);

    connect_upstream();
    time_t last_heartbeat = time(NULL);

    while (1) {
        struct pollfd fds[MAX_STREAMS + 4];
        int nfds = 0;

        fds[nfds].fd = socks_fd; fds[nfds].events = POLLIN; nfds++;
        fds[nfds].fd = redir_fd; fds[nfds].events = POLLIN; nfds++;
        fds[nfds].fd = g_dns_fd; fds[nfds].events = POLLIN; nfds++;

        int ssl_idx = -1;
        if (g_ssl && g_ssl_fd >= 0) {
            ssl_idx = nfds;
            fds[nfds].fd = g_ssl_fd; fds[nfds].events = POLLIN; nfds++;
        }

        int stream_map[MAX_STREAMS + 4];
        for (int i = 0; i < MAX_STREAMS; i++) {
            if (g_streams[i].client_fd > 0) {
                stream_map[nfds] = i;
                fds[nfds].fd = g_streams[i].client_fd;
                fds[nfds].events = POLLIN;
                nfds++;
            }
        }

        int ret = poll(fds, nfds, 1000);
        if (ret < 0 && errno == EINTR) continue;

        time_t now = time(NULL);
        if (now - last_heartbeat >= 20) {
            if (g_ssl) {
                send_frame(CMD_HEART_REQ, 0, NULL, 0);
            } else {
                connect_upstream();
            }
            last_heartbeat = now;
        }

        if (ret > 0) {
            if (fds[0].revents & POLLIN) handle_new_connection(socks_fd, 0);
            if (fds[1].revents & POLLIN) handle_new_connection(redir_fd, 1);
            if (fds[2].revents & POLLIN) handle_dns_udp_query();
            if (ssl_idx >= 0 && (fds[ssl_idx].revents & (POLLIN | POLLERR | POLLHUP))) {
                handle_upstream_data();
            }

            for (int j = (ssl_idx >= 0 ? 4 : 3); j < nfds; j++) {
                if (fds[j].revents & (POLLIN | POLLERR | POLLHUP)) {
                    int sidx = stream_map[j];
                    handle_client_data(&g_streams[sidx]);
                }
            }
        }
    }

    return 0;
}

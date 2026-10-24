/*
 * smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client
 *
 * Designed for embedded Linux / OpenWrt routers with severe storage constraints.
 * Binary footprint: ~25 KB (stripped).
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

#define FRAME_HDR 7
#define MAX_STREAMS 256
#define MAX_DNS_REQS 64
#define RX_BUF_SIZE (128 * 1024)
#define TX_BUF_SIZE (128 * 1024)
/* Stop reading LAN clients while this much tunnel output is still unsent */
#define TX_HIGH_WATER (64 * 1024)
/* One PSH frame (header + data) fills exactly one 16 KB TLS record */
#define CLIENT_READ_SIZE (16384 - FRAME_HDR)
/* Per-stream / total downstream backlog before the tunnel stops reading */
#define WBUF_STREAM_MAX (256 * 1024)
#define WBUF_TOTAL_MAX (2 * 1024 * 1024)
/* A stream that blocks the tunnel this long without draining is dropped */
#define STALL_TIMEOUT 10
#define IDLE_WRITE_TIMEOUT 60
#define HEARTBEAT_IDLE 15
#define DEAD_TIMEOUT 45
#define DNS_TIMEOUT 6
#define MAX_BACKOFF 30

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
static unsigned char* (*p_SHA256)(const unsigned char*, size_t, unsigned char*);

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_CTRL_MODE 33
#define SSL_MODE_ENABLE_PARTIAL_WRITE 0x1
#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x2
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
    p_SHA256 = dlsym(h_crypto, "SHA256");

    if (!p_TLS_client_method || !p_SSL_CTX_new || !p_SSL_CTX_set_verify || !p_SSL_new ||
        !p_SSL_set_fd || !p_SSL_ctrl || !p_SSL_set_alpn_protos || !p_SSL_connect ||
        !p_SSL_read || !p_SSL_write || !p_SSL_get_error || !p_SSL_shutdown ||
        !p_SSL_free || !p_SHA256) {
        fprintf(stderr, "[anytls-tiny] Error: Failed to resolve required OpenSSL symbols: %s\n", dlerror());
        return -1;
    }
    return 0;
}

/* Stream tracking */
typedef struct {
    uint32_t stream_id;   /* 0 until cmdSYN has been sent */
    int client_fd;
    uint8_t is_redir;
    uint8_t socks_state;  /* 0: auth, 1: req, 2: connected */
    uint8_t remote_fin;   /* server closed the stream; close once wbuf drains */
    /* Downstream data the LAN client could not accept yet */
    uint8_t *wbuf;
    int wlen, woff, wcap;
    time_t wprogress;
} stream_t;

typedef struct {
    uint32_t stream_id;   /* 0 = slot free */
    struct sockaddr_in client_addr;
    time_t expire;
    uint8_t *rbuf;        /* reassembly of a reply split across PSH frames */
    int rlen;
} dns_req_t;

static stream_t  g_streams[MAX_STREAMS];
static dns_req_t g_dns_reqs[MAX_DNS_REQS];
static int       g_dns_active = 0;
static uint32_t  g_stream_counter = 1;

static SSL_CTX *g_ssl_ctx = NULL;
static SSL     *g_ssl = NULL;
static int      g_ssl_fd = -1;
static int      g_upstream_broken = 0;
static int      g_peer_version = 0;
static int      g_backoff = 0;
static time_t   g_next_connect = 0;
static time_t   g_connected_at = 0;
static time_t   g_last_rx = 0;
static time_t   g_last_hb = 0;

/* Static BSS buffers */
static uint8_t g_rx_buf[RX_BUF_SIZE];
static int     g_rx_len = 0;
static int     g_rx_kick = 0;        /* frames may be waiting without a POLLIN */
static int     g_rx_want_write = 0;  /* SSL_read asked for POLLOUT */
static uint8_t g_tx_buf[TX_BUF_SIZE];
static int     g_tx_off = 0, g_tx_len = 0;
static int     g_tx_inflight = 0;    /* length of an SSL_write that must be retried */
static int     g_tx_want_write = 0;
static uint8_t g_client_rx_buf[CLIENT_READ_SIZE];
static long    g_wbuf_total = 0;

static char g_server_host[256] = "";
static int  g_server_port = 443;
static char g_password[256] = "";
static char g_sni[256] = "";
static char g_bind_addr[64] = "0.0.0.0";
static int  g_socks_port = 1080;
static int  g_redir_port = 1100;
static int  g_dns_port = 5353;
static int  g_dns_fd = -1;
/* SOCKS5-style address of the DNS resolver reached through the tunnel */
static uint8_t g_dns_target[7] = { 0x01, 8, 8, 8, 8, 0, 53 };

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_nodelay(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int tx_pending(void) {
    return g_tx_len - g_tx_off;
}

/* Write as much of the TX buffer as the socket accepts without blocking. */
static void flush_tx(void) {
    while (g_ssl && !g_upstream_broken && g_tx_off < g_tx_len) {
        /* A retried SSL_write must repeat the exact same buffer and length */
        int len = g_tx_inflight ? g_tx_inflight : g_tx_len - g_tx_off;
        int n = p_SSL_write(g_ssl, g_tx_buf + g_tx_off, len);
        if (n <= 0) {
            int err = p_SSL_get_error(g_ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                g_tx_inflight = len;
                g_tx_want_write = (err == SSL_ERROR_WANT_WRITE);
                return;
            }
            fprintf(stderr, "[anytls-tiny] Upstream write failed (err=%d)\n", err);
            g_upstream_broken = 1;
            return;
        }
        g_tx_inflight = 0;
        g_tx_off += n;
    }
    g_tx_want_write = 0;
    if (g_tx_off == g_tx_len) g_tx_off = g_tx_len = 0;
}

static int tx_reserve(int need) {
    if (g_tx_len + need <= TX_BUF_SIZE) return 0;
    flush_tx();
    if (g_tx_off > 0 && !g_tx_inflight) {
        memmove(g_tx_buf, g_tx_buf + g_tx_off, g_tx_len - g_tx_off);
        g_tx_len -= g_tx_off;
        g_tx_off = 0;
    }
    /* Still full: the uplink is congested, wait for it to drain */
    for (int tries = 0; g_tx_len + need > TX_BUF_SIZE; tries++) {
        if (!g_ssl || g_upstream_broken || tries >= 10) {
            g_upstream_broken = 1;
            return -1;
        }
        struct pollfd pfd = { .fd = g_ssl_fd, .events = g_tx_want_write ? POLLOUT : POLLIN };
        poll(&pfd, 1, 1000);
        flush_tx();
        if (g_tx_off > 0 && !g_tx_inflight) {
            memmove(g_tx_buf, g_tx_buf + g_tx_off, g_tx_len - g_tx_off);
            g_tx_len -= g_tx_off;
            g_tx_off = 0;
        }
    }
    return 0;
}

/*
 * Frames are batched in the TX buffer and flushed once per event-loop pass,
 * so small control frames share TLS records with data instead of each
 * costing their own record and TCP segment.
 */
static int queue_frame(uint8_t cmd, uint32_t stream_id, const uint8_t *data, uint16_t len) {
    if (!g_ssl || g_upstream_broken) return -1;
    if (tx_reserve(FRAME_HDR + len) < 0) return -1;

    uint8_t *p = g_tx_buf + g_tx_len;
    p[0] = cmd;
    p[1] = (stream_id >> 24) & 0xFF;
    p[2] = (stream_id >> 16) & 0xFF;
    p[3] = (stream_id >> 8) & 0xFF;
    p[4] = stream_id & 0xFF;
    p[5] = (len >> 8) & 0xFF;
    p[6] = len & 0xFF;
    if (len > 0 && data) {
        memcpy(p + FRAME_HDR, data, len);
    }
    g_tx_len += FRAME_HDR + len;
    return 0;
}

static stream_t *find_stream_by_id(uint32_t sid) {
    if (sid == 0) return NULL;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0 && g_streams[i].stream_id == sid)
            return &g_streams[i];
    }
    return NULL;
}

static stream_t *alloc_stream(int client_fd, int is_redir) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd <= 0) {
            memset(&g_streams[i], 0, sizeof(g_streams[i]));
            g_streams[i].client_fd = client_fd;
            g_streams[i].is_redir = is_redir;
            g_streams[i].socks_state = is_redir ? 2 : 0;
            return &g_streams[i];
        }
    }
    return NULL;
}

/* Send cmdSYN + target address; stream IDs are assigned in SYN order */
static int open_remote_stream(stream_t *st, const uint8_t *addr, int addr_len) {
    st->stream_id = g_stream_counter;
    g_stream_counter += 2; /* Client stream IDs are odd */
    if (queue_frame(CMD_SYN, st->stream_id, NULL, 0) < 0) return -1;
    return queue_frame(CMD_PSH, st->stream_id, addr, addr_len);
}

static void close_stream(stream_t *st) {
    if (!st || st->client_fd <= 0) return;
    /* Per spec, a stream closed by the server is not answered with FIN */
    if (st->stream_id && !st->remote_fin) {
        queue_frame(CMD_FIN, st->stream_id, NULL, 0);
    }
    close(st->client_fd);
    g_wbuf_total -= st->wlen - st->woff;
    free(st->wbuf);
    memset(st, 0, sizeof(*st));
    st->client_fd = -1;
}

/* Deliver downstream data to a LAN client, buffering whatever it can't take yet */
static int stream_write(stream_t *st, const uint8_t *data, int len) {
    if (st->woff == st->wlen) {
        while (len > 0) {
            int n = send(st->client_fd, data, len, MSG_NOSIGNAL);
            if (n > 0) { data += n; len -= n; continue; }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            return -1;
        }
        if (len == 0) return 0;
        st->wprogress = time(NULL);
    }
    if (st->wlen + len > st->wcap && st->woff > 0) {
        memmove(st->wbuf, st->wbuf + st->woff, st->wlen - st->woff);
        st->wlen -= st->woff;
        st->woff = 0;
    }
    if (st->wlen + len > st->wcap) {
        int ncap = st->wcap ? st->wcap : 16384;
        while (ncap < st->wlen + len) ncap *= 2;
        uint8_t *nb = realloc(st->wbuf, ncap);
        if (!nb) return -1;
        st->wbuf = nb;
        st->wcap = ncap;
    }
    memcpy(st->wbuf + st->wlen, data, len);
    st->wlen += len;
    g_wbuf_total += len;
    return 0;
}

static void stream_flush(stream_t *st) {
    while (st->woff < st->wlen) {
        int n = send(st->client_fd, st->wbuf + st->woff, st->wlen - st->woff, MSG_NOSIGNAL);
        if (n > 0) {
            st->woff += n;
            g_wbuf_total -= n;
            st->wprogress = time(NULL);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        close_stream(st);
        return;
    }
    st->woff = st->wlen = 0;
    if (st->wcap > 65536) {
        free(st->wbuf);
        st->wbuf = NULL;
        st->wcap = 0;
    }
    if (st->remote_fin) close_stream(st);
}

/* Backpressure: stop reading the tunnel while LAN clients are too far behind */
static int rx_paused(void) {
    if (g_wbuf_total <= WBUF_STREAM_MAX) return 0;
    if (g_wbuf_total > WBUF_TOTAL_MAX) return 1;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0 && g_streams[i].wlen - g_streams[i].woff > WBUF_STREAM_MAX)
            return 1;
    }
    return 0;
}

static dns_req_t *find_dns_req(uint32_t sid) {
    if (!g_dns_active || sid == 0) return NULL;
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (g_dns_reqs[i].stream_id == sid) return &g_dns_reqs[i];
    }
    return NULL;
}

static void release_dns_req(dns_req_t *d, int send_fin) {
    if (!d->stream_id) return;
    if (send_fin) queue_frame(CMD_FIN, d->stream_id, NULL, 0);
    free(d->rbuf);
    memset(d, 0, sizeof(*d));
    g_dns_active--;
}

static void close_all_streams(void) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0) {
            close(g_streams[i].client_fd);
            free(g_streams[i].wbuf);
            memset(&g_streams[i], 0, sizeof(g_streams[i]));
            g_streams[i].client_fd = -1;
        }
    }
    g_wbuf_total = 0;
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        release_dns_req(&g_dns_reqs[i], 0);
    }
}

static void bump_backoff(time_t now) {
    g_backoff = g_backoff ? (g_backoff * 2 > MAX_BACKOFF ? MAX_BACKOFF : g_backoff * 2) : 1;
    g_next_connect = now + g_backoff;
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
    /* A session that dies right after connecting (e.g. wrong password) also backs off */
    time_t now = time(NULL);
    if (g_connected_at && now - g_connected_at < 10) bump_backoff(now);
    g_connected_at = 0;
    g_upstream_broken = 0;
    g_peer_version = 0;
    g_rx_len = 0;
    g_rx_kick = 0;
    g_rx_want_write = 0;
    g_tx_off = g_tx_len = g_tx_inflight = 0;
    g_tx_want_write = 0;
    close_all_streams();
}

static int connect_upstream(void) {
    time_t now = time(NULL);
    if (now < g_next_connect) return -1;

    disconnect_upstream();
    printf("[anytls-tiny] Connecting to upstream %s:%d (SNI: %s)...\n", g_server_host, g_server_port, g_sni);
    fflush(stdout);

    /* Assume failure until the handshake completes */
    bump_backoff(now);

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

    /* Bounds the blocking connect + handshake below */
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(g_ssl_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(g_ssl_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    set_tcp_nodelay(g_ssl_fd);

    /* Detect silently dropped connections (NAT timeouts, dead servers) */
    int one = 1, idle = 30, intvl = 10, cnt = 3;
    setsockopt(g_ssl_fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    setsockopt(g_ssl_fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(g_ssl_fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(g_ssl_fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));

    if (connect(g_ssl_fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("[anytls-tiny] Connect error");
        close(g_ssl_fd);
        g_ssl_fd = -1;
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    g_ssl = p_SSL_new(g_ssl_ctx);
    if (!g_ssl) {
        disconnect_upstream();
        return -1;
    }
    p_SSL_set_fd(g_ssl, g_ssl_fd);
    p_SSL_ctrl(g_ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, g_sni);
    p_SSL_ctrl(g_ssl, SSL_CTRL_MODE, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, NULL);

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

    /* 1. Auth Header: SHA256(password) + uint16(30) + 30 zero bytes, sent on its own */
    uint8_t auth[32 + 2 + 30];
    p_SHA256((const unsigned char *)g_password, strlen(g_password), auth);
    auth[32] = 0;
    auth[33] = 30;
    memset(auth + 34, 0, 30);

    if (p_SSL_write(g_ssl, auth, sizeof(auth)) <= 0) {
        disconnect_upstream();
        return -1;
    }

    set_nonblock(g_ssl_fd);
    g_rx_len = 0;
    g_connected_at = g_last_rx = g_last_hb = now;

    /* 2. cmdSettings is queued so it shares a TLS record with the first SYN */
    static const char settings_data[] = "v=2\nclient=anytls/0.0.1\npadding-md5=00000000000000000000000000000000\n";
    queue_frame(CMD_SETTINGS, 0, (const uint8_t *)settings_data, sizeof(settings_data) - 1);

    printf("[anytls-tiny] AnyTLS Auth + Settings sent successfully! Ready for traffic.\n");
    fflush(stdout);
    g_next_connect = 0;
    return 0;
}

static int bind_listener(int type, const char *addr, int port) {
    if (port <= 0) return -1;
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    set_nonblock(fd);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, addr, &sin.sin_addr) != 1) {
        fprintf(stderr, "[anytls-tiny] Invalid listen address %s\n", addr);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror(type == SOCK_STREAM ? "bind tcp" : "bind udp");
        close(fd);
        return -1;
    }
    if (type == SOCK_STREAM) listen(fd, 128);
    return fd;
}

static void handle_new_connection(int listen_fd, int is_redir) {
    /* Drain the accept queue so bursts (page loads) don't wait a poll round each */
    for (int k = 0; k < 16; k++) {
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd < 0) return;

        set_nonblock(cfd);
        set_tcp_nodelay(cfd);

        if (!g_ssl && connect_upstream() < 0) {
            close(cfd);
            continue;
        }

        stream_t *st = alloc_stream(cfd, is_redir);
        if (!st) {
            fprintf(stderr, "[anytls-tiny] Stream table full (%d), dropping connection\n", MAX_STREAMS);
            close(cfd);
            continue;
        }

        if (is_redir) {
            struct sockaddr_in orig_dst;
            socklen_t dlen = sizeof(orig_dst);
            if (getsockopt(cfd, SOL_IP, SO_ORIGINAL_DST, &orig_dst, &dlen) < 0) {
                close_stream(st);
                continue;
            }

            uint8_t socks_addr[7];
            socks_addr[0] = 0x01; /* IPv4 */
            memcpy(socks_addr + 1, &orig_dst.sin_addr.s_addr, 4);
            memcpy(socks_addr + 5, &orig_dst.sin_port, 2);

            if (open_remote_stream(st, socks_addr, 7) < 0) close_stream(st);
        }
    }
}

/* SOCKS5 greeting and CONNECT request; tolerates both arriving in one segment */
static void handle_socks_handshake(stream_t *st) {
    int n = recv(st->client_fd, g_client_rx_buf, sizeof(g_client_rx_buf), 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    if (n <= 0) { close_stream(st); return; }
    uint8_t *p = g_client_rx_buf;

    if (st->socks_state == 0) {
        if (n < 2 || p[0] != 0x05 || n < 2 + p[1]) { close_stream(st); return; }
        static const uint8_t auth_ok[2] = { 0x05, 0x00 };
        if (stream_write(st, auth_ok, 2) < 0) { close_stream(st); return; }
        st->socks_state = 1;
        int used = 2 + p[1];
        p += used;
        n -= used;
        if (n == 0) return;
    }

    uint8_t resp[10] = { 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
    if (n < 5 || p[0] != 0x05) { close_stream(st); return; }
    if (p[1] != 0x01) {
        resp[1] = 0x07; /* command not supported */
        stream_write(st, resp, 10);
        close_stream(st);
        return;
    }

    uint8_t *saddr = p + 3;
    int saddr_len;
    if (saddr[0] == 0x01) saddr_len = 1 + 4 + 2;
    else if (saddr[0] == 0x03) saddr_len = 1 + 1 + saddr[1] + 2;
    else if (saddr[0] == 0x04) saddr_len = 1 + 16 + 2;
    else {
        resp[1] = 0x08; /* address type not supported */
        stream_write(st, resp, 10);
        close_stream(st);
        return;
    }
    if (n < 3 + saddr_len) { close_stream(st); return; }

    if (open_remote_stream(st, saddr, saddr_len) < 0 || stream_write(st, resp, 10) < 0) {
        close_stream(st);
        return;
    }
    st->socks_state = 2;

    /* Forward any early data the client sent along with the request */
    int rest = n - 3 - saddr_len;
    if (rest > 0 && queue_frame(CMD_PSH, st->stream_id, saddr + saddr_len, rest) < 0) {
        close_stream(st);
    }
}

static void handle_client_data(stream_t *st) {
    if (st->socks_state < 2) {
        handle_socks_handshake(st);
        return;
    }

    /* Bounded per pass so one bulk upload can't starve other clients */
    for (int k = 0; k < 4 && tx_pending() < TX_HIGH_WATER; k++) {
        int n = recv(st->client_fd, g_client_rx_buf, sizeof(g_client_rx_buf), 0);
        if (n > 0) {
            if (queue_frame(CMD_PSH, st->stream_id, g_client_rx_buf, n) < 0) {
                close_stream(st);
                return;
            }
            if (n < (int)sizeof(g_client_rx_buf)) return;
        } else if (n == 0) {
            close_stream(st);
            return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            close_stream(st);
            return;
        }
    }
}

static void handle_dns_udp_query(void) {
    uint8_t buf[2 + 2048];
    struct sockaddr_in cli;
    socklen_t clen = sizeof(cli);
    int n = recvfrom(g_dns_fd, buf + 2, sizeof(buf) - 2, 0, (struct sockaddr *)&cli, &clen);
    if (n <= 12) return;

    if (!g_ssl && connect_upstream() < 0) return;

    dns_req_t *d = NULL;
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (!g_dns_reqs[i].stream_id) {
            d = &g_dns_reqs[i];
            break;
        }
    }
    if (!d) return;

    d->stream_id = g_stream_counter;
    g_stream_counter += 2;
    d->client_addr = cli;
    d->expire = time(NULL) + DNS_TIMEOUT;
    g_dns_active++;

    /* One stream per query to the configured resolver, query sent with 2-byte length prefix */
    buf[0] = (n >> 8) & 0xFF;
    buf[1] = n & 0xFF;
    if (queue_frame(CMD_SYN, d->stream_id, NULL, 0) < 0 ||
        queue_frame(CMD_PSH, d->stream_id, g_dns_target, sizeof(g_dns_target)) < 0 ||
        queue_frame(CMD_PSH, d->stream_id, buf, 2 + n) < 0) {
        release_dns_req(d, 0);
    }
}

static void dns_reply(dns_req_t *d, const uint8_t *msg, int len) {
    sendto(g_dns_fd, msg, len, 0, (struct sockaddr *)&d->client_addr, sizeof(d->client_addr));
    release_dns_req(d, 1);
}

/* DNS-over-TCP replies may be split across several PSH frames */
static void handle_dns_data(dns_req_t *d, const uint8_t *data, int len) {
    if (d->rlen == 0 && len >= 2) {
        int mlen = (data[0] << 8) | data[1];
        if (len >= 2 + mlen) {
            dns_reply(d, data + 2, mlen);
            return;
        }
    }
    uint8_t *nb = realloc(d->rbuf, d->rlen + len);
    if (!nb) {
        release_dns_req(d, 1);
        return;
    }
    d->rbuf = nb;
    memcpy(d->rbuf + d->rlen, data, len);
    d->rlen += len;
    if (d->rlen >= 2) {
        int mlen = (d->rbuf[0] << 8) | d->rbuf[1];
        if (d->rlen >= 2 + mlen) dns_reply(d, d->rbuf + 2, mlen);
    }
}

static void handle_frame(uint8_t cmd, uint32_t sid, const uint8_t *data, int len) {
    dns_req_t *d;
    stream_t *st;

    switch (cmd) {
    case CMD_PSH:
        if ((d = find_dns_req(sid))) {
            handle_dns_data(d, data, len);
        } else if ((st = find_stream_by_id(sid)) && !st->remote_fin) {
            if (stream_write(st, data, len) < 0) close_stream(st);
        }
        break;
    case CMD_FIN:
        if ((d = find_dns_req(sid))) release_dns_req(d, 0);
        if ((st = find_stream_by_id(sid))) {
            st->remote_fin = 1;
            if (st->woff == st->wlen) close_stream(st);
        }
        break;
    case CMD_SYNACK:
        /* Non-empty payload: the server could not reach the target */
        if (len > 0) {
            printf("[anytls-tiny] Stream %u rejected by server: %.*s\n", sid, len > 200 ? 200 : len, (const char *)data);
            fflush(stdout);
            if ((d = find_dns_req(sid))) release_dns_req(d, 1);
            if ((st = find_stream_by_id(sid))) close_stream(st);
        }
        break;
    case CMD_HEART_REQ:
        queue_frame(CMD_HEART_RESP, sid, NULL, 0);
        break;
    case CMD_SERVER_SETTINGS:
        for (int i = 0; i + 2 < len; i++) {
            if ((i == 0 || data[i - 1] == '\n') && data[i] == 'v' && data[i + 1] == '=') {
                g_peer_version = atoi((const char *)data + i + 2);
                break;
            }
        }
        break;
    case CMD_ALERT:
        fprintf(stderr, "[anytls-tiny] Alert from server: %.*s\n", len > 200 ? 200 : len, (const char *)data);
        g_upstream_broken = 1;
        break;
    default:
        /* cmdWaste, cmdUpdatePaddingScheme, cmdHeartResponse: nothing to do */
        break;
    }
}

/* Parse all complete frames in the RX buffer; returns -1 if parsing had to stop early */
static int parse_rx_frames(void) {
    int off = 0, ret = 0;
    while (g_rx_len - off >= FRAME_HDR) {
        if (rx_paused()) { ret = -1; break; }
        const uint8_t *h = g_rx_buf + off;
        uint32_t sid = ((uint32_t)h[1] << 24) | ((uint32_t)h[2] << 16) |
                       ((uint32_t)h[3] << 8)  | (uint32_t)h[4];
        int flen = (h[5] << 8) | h[6];
        if (g_rx_len - off < FRAME_HDR + flen) break;

        handle_frame(h[0], sid, h + FRAME_HDR, flen);
        off += FRAME_HDR + flen;
        if (g_upstream_broken) return -1;
    }
    if (off > 0) {
        memmove(g_rx_buf, g_rx_buf + off, g_rx_len - off);
        g_rx_len -= off;
    }
    return ret;
}

static void handle_upstream_data(void) {
    g_rx_kick = 0;
    g_rx_want_write = 0;
    /* Drain several TLS records per wakeup instead of one per poll() */
    for (int iter = 0; iter < 16; iter++) {
        if (parse_rx_frames() < 0) {
            if (!g_upstream_broken) g_rx_kick = 1;
            return;
        }
        /* After parsing only a partial frame (< 64 KB) remains, so there is always room */
        int n = p_SSL_read(g_ssl, g_rx_buf + g_rx_len, RX_BUF_SIZE - g_rx_len);
        if (n <= 0) {
            int err = p_SSL_get_error(g_ssl, n);
            if (err == SSL_ERROR_WANT_READ) return;
            if (err == SSL_ERROR_WANT_WRITE) { g_rx_want_write = 1; return; }
            printf("[anytls-tiny] Upstream SSL disconnected (err=%d)\n", err);
            fflush(stdout);
            g_upstream_broken = 1;
            return;
        }
        g_rx_len += n;
        g_last_rx = time(NULL);
    }
    g_rx_kick = 1;
}

/* Once-a-second housekeeping: heartbeats, dead-session detection, timeouts */
static void periodic_tick(time_t now) {
    if (!g_ssl) {
        if (now >= g_next_connect) connect_upstream();
        return;
    }

    /* Only a session that stays up resets the reconnect backoff */
    if (g_backoff && now - g_connected_at >= 10) g_backoff = 0;

    int paused = rx_paused();
    if (paused) g_last_rx = now; /* unread data is waiting in the kernel, the session is alive */

    if (g_peer_version >= 2) {
        if (now - g_last_rx >= HEARTBEAT_IDLE && now - g_last_hb >= HEARTBEAT_IDLE) {
            queue_frame(CMD_HEART_REQ, 0, NULL, 0);
            g_last_hb = now;
        }
        if (now - g_last_rx >= DEAD_TIMEOUT) {
            printf("[anytls-tiny] No data from server for %ds, reconnecting\n", DEAD_TIMEOUT);
            fflush(stdout);
            g_upstream_broken = 1;
            return;
        }
    }

    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (g_dns_reqs[i].stream_id && now >= g_dns_reqs[i].expire)
            release_dns_req(&g_dns_reqs[i], 1);
    }

    /* Drop clients that stopped reading: they would otherwise stall every other stream */
    for (int i = 0; i < MAX_STREAMS; i++) {
        stream_t *st = &g_streams[i];
        int pending = st->wlen - st->woff;
        if (st->client_fd <= 0 || pending == 0) continue;
        if ((pending > WBUF_STREAM_MAX && now - st->wprogress >= STALL_TIMEOUT) ||
            now - st->wprogress >= IDLE_WRITE_TIMEOUT) {
            close_stream(st);
        }
    }
}

static int parse_dns_target(const char *s) {
    char host[64];
    int port = 53;
    strncpy(host, s, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    char *colon = strchr(host, ':');
    if (colon) {
        *colon = '\0';
        port = atoi(colon + 1);
    }
    struct in_addr a;
    if (inet_pton(AF_INET, host, &a) != 1 || port <= 0 || port > 65535) return -1;
    g_dns_target[0] = 0x01;
    memcpy(g_dns_target + 1, &a, 4);
    g_dns_target[5] = (port >> 8) & 0xFF;
    g_dns_target[6] = port & 0xFF;
    return 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client\n\n");
    fprintf(stderr, "Usage: %s -s <server> -p <port> -k <password> -h <sni> [options]\n\n", prog);
    fprintf(stderr, "Required options:\n");
    fprintf(stderr, "  -s <host/ip>    Upstream AnyTLS server address\n");
    fprintf(stderr, "  -p <port>       Upstream AnyTLS server port (e.g. 443)\n");
    fprintf(stderr, "  -k <password>   AnyTLS authentication password or UUID\n");
    fprintf(stderr, "  -h <sni>        TLS Server Name Indication (SNI, e.g. www.apple.com)\n\n");
    fprintf(stderr, "Optional:\n");
    fprintf(stderr, "  -l <port>       Local SOCKS5 proxy port (default: 1080, 0 = off)\n");
    fprintf(stderr, "  -r <port>       Transparent redirect port (SO_ORIGINAL_DST, default: 1100, 0 = off)\n");
    fprintf(stderr, "  -u <port>       DNS-over-TCP UDP listening port (default: 5353, 0 = off)\n");
    fprintf(stderr, "  -n <ip[:port]>  DNS resolver reached through the tunnel (default: 8.8.8.8:53)\n");
    fprintf(stderr, "  -b <ip>         Listen address for SOCKS5 and DNS (default: 0.0.0.0)\n");
    fprintf(stderr, "  -d              Run as background daemon\n");
}

int main(int argc, char **argv) {
    int opt, daemonize = 0;
    while ((opt = getopt(argc, argv, "s:p:k:h:l:r:u:n:b:d")) != -1) {
        switch (opt) {
            case 's': strncpy(g_server_host, optarg, sizeof(g_server_host)-1); break;
            case 'p': g_server_port = atoi(optarg); break;
            case 'k': strncpy(g_password, optarg, sizeof(g_password)-1); break;
            case 'h': strncpy(g_sni, optarg, sizeof(g_sni)-1); break;
            case 'l': g_socks_port = atoi(optarg); break;
            case 'r': g_redir_port = atoi(optarg); break;
            case 'u': g_dns_port = atoi(optarg); break;
            case 'n':
                if (parse_dns_target(optarg) < 0) {
                    fprintf(stderr, "[anytls-tiny] Error: invalid DNS resolver '%s' (expected IPv4[:port])\n", optarg);
                    return 1;
                }
                break;
            case 'b': strncpy(g_bind_addr, optarg, sizeof(g_bind_addr)-1); break;
            case 'd': daemonize = 1; break;
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
    if (!g_ssl_ctx) {
        fprintf(stderr, "[anytls-tiny] Error: SSL_CTX_new failed\n");
        return 1;
    }
    p_SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);

    /* Redirect must accept on the LAN address nftables redirects to, so it always binds all */
    int socks_fd = bind_listener(SOCK_STREAM, g_bind_addr, g_socks_port);
    int redir_fd = bind_listener(SOCK_STREAM, "0.0.0.0", g_redir_port);
    g_dns_fd = bind_listener(SOCK_DGRAM, g_bind_addr, g_dns_port);

    if ((g_socks_port > 0 && socks_fd < 0) || (g_redir_port > 0 && redir_fd < 0) ||
        (g_dns_port > 0 && g_dns_fd < 0)) {
        fprintf(stderr, "[anytls-tiny] Failed to bind local ports (socks:%d, redir:%d, dns:%d)\n",
                g_socks_port, g_redir_port, g_dns_port);
        return 1;
    }

    if (daemonize && daemon(1, 1) < 0) {
        perror("daemon");
        return 1;
    }

    printf("[anytls-tiny] Started! SOCKS5:%d, Redir:%d, DNS-UDP:%d\n", g_socks_port, g_redir_port, g_dns_port);
    fflush(stdout);

    connect_upstream();
    time_t last_tick = time(NULL);

    struct pollfd fds[MAX_STREAMS + 4];
    int stream_map[MAX_STREAMS + 4];

    while (1) {
        /* Fixed slots 0-3; poll() ignores entries whose fd is -1 */
        int paused = rx_paused();
        fds[0].fd = socks_fd; fds[0].events = POLLIN;
        fds[1].fd = redir_fd; fds[1].events = POLLIN;
        fds[2].fd = g_dns_fd; fds[2].events = POLLIN;
        fds[3].fd = g_ssl ? g_ssl_fd : -1;
        fds[3].events = (paused ? 0 : POLLIN) | (g_tx_want_write || g_rx_want_write ? POLLOUT : 0);
        int nfds = 4;

        int tx_full = tx_pending() >= TX_HIGH_WATER;
        for (int i = 0; i < MAX_STREAMS; i++) {
            stream_t *st = &g_streams[i];
            if (st->client_fd <= 0) continue;
            short ev = 0;
            if (!st->remote_fin && !tx_full) ev |= POLLIN;
            if (st->woff < st->wlen) ev |= POLLOUT;
            stream_map[nfds] = i;
            fds[nfds].fd = st->client_fd;
            fds[nfds].events = ev;
            nfds++;
        }

        int ret = poll(fds, nfds, (g_rx_kick && !paused && g_ssl) ? 0 : 1000);
        if (ret < 0 && errno != EINTR) {
            perror("poll");
            return 1;
        }
        if (ret < 0) continue;

        time_t now = time(NULL);
        if (now != last_tick) {
            periodic_tick(now);
            last_tick = now;
        }

        if (ret > 0) {
            if (fds[0].revents & POLLIN) handle_new_connection(socks_fd, 0);
            if (fds[1].revents & POLLIN) handle_new_connection(redir_fd, 1);
            if (fds[2].revents & POLLIN) handle_dns_udp_query();
        }

        if (g_ssl && fds[3].fd == g_ssl_fd) {
            short re = fds[3].revents;
            if (re & POLLOUT) flush_tx();
            if (paused && (re & (POLLERR | POLLHUP))) {
                g_upstream_broken = 1;
            } else if ((re & (POLLIN | POLLERR | POLLHUP)) || (g_rx_kick && !paused) ||
                       (g_rx_want_write && (re & POLLOUT))) {
                handle_upstream_data();
            }
        }

        if (ret > 0) {
            for (int j = 4; j < nfds; j++) {
                stream_t *st = &g_streams[stream_map[j]];
                /* The slot may have been closed earlier in this pass */
                if (!fds[j].revents || st->client_fd != fds[j].fd) continue;
                if (fds[j].revents & POLLOUT) stream_flush(st);
                if (st->client_fd != fds[j].fd) continue;
                if (fds[j].revents & POLLIN) handle_client_data(st);
                else if (fds[j].revents & (POLLERR | POLLHUP)) close_stream(st);
            }
        }

        if (!g_upstream_broken) flush_tx();
        if (g_upstream_broken) disconnect_upstream();
    }

    return 0;
}

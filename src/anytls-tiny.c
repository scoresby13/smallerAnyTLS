/*
 * smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client
 *
 * Designed for embedded Linux / OpenWrt routers with severe storage constraints.
 * Binary footprint: ~25 KB (stripped).
 * Dependencies: libc, libdl (dynamically loads OpenSSL from firmware ROM).
 *
 * Supports:
 *  - AnyTLS v2 multiplexed TLS tunnel with a session pool
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
#define MAX_STREAMS 512
#define MAX_DNS_REQS 64
/* Hard upper bound for -m; each live session costs one TLS connection */
#define MAX_SESSIONS 32
/* Per-session buffers, allocated on demand and released while the session is idle.
 * RX holds one maximum-size frame (7 + 65535 bytes) with a little slack. */
#define RX_BUF_SIZE (64 * 1024 + 16)
#define TX_BUF_SIZE (64 * 1024)
/* Stop reading a session's LAN clients while this much tunnel output is still unsent */
#define TX_HIGH_WATER (32 * 1024)
/* One PSH frame (header + data) fills exactly one 16 KB TLS record */
#define CLIENT_READ_SIZE (16384 - FRAME_HDR)
/* Per-stream / total downstream backlog before a session stops reading */
#define WBUF_STREAM_MAX (256 * 1024)
#define WBUF_TOTAL_MAX (2 * 1024 * 1024)
/* A stream that blocks its session this long without draining is dropped */
#define STALL_TIMEOUT 10
#define IDLE_WRITE_TIMEOUT 60
#define STREAM_IDLE_TIMEOUT 180
#define STREAM_HANDSHAKE_TIMEOUT 30
#define HEARTBEAT_IDLE 15
#define DNS_TIMEOUT 6
#define MAX_BACKOFF 30
/* Padding: max records per packet, largest record size */
#define PAD_MAX_REC 16
#define PAD_MAX_SIZE 16384
/* TCP connect + TLS handshake must finish within this many seconds */
#define CONNECT_TIMEOUT 10
#define IDLE_CHECK_INTERVAL 30
#define RESOLVE_TTL 120

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
static int (*p_RAND_bytes)(unsigned char*, int);
static int (*p_EVP_Digest)(const void*, size_t, unsigned char*, unsigned int*, const void*, void*);
static const void* (*p_EVP_md5)(void);
static void (*p_ERR_clear_error)(void);

#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define SSL_CTRL_MODE 33
#define SSL_MODE_ENABLE_PARTIAL_WRITE 0x1
#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x2
#define SSL_MODE_RELEASE_BUFFERS 0x10
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
    p_RAND_bytes = dlsym(h_crypto, "RAND_bytes");
    p_EVP_Digest = dlsym(h_crypto, "EVP_Digest");
    p_EVP_md5 = dlsym(h_crypto, "EVP_md5");
    p_ERR_clear_error = dlsym(h_crypto, "ERR_clear_error");

    if (!p_TLS_client_method || !p_SSL_CTX_new || !p_SSL_CTX_set_verify || !p_SSL_new ||
        !p_SSL_set_fd || !p_SSL_ctrl || !p_SSL_set_alpn_protos || !p_SSL_connect ||
        !p_SSL_read || !p_SSL_write || !p_SSL_get_error || !p_SSL_shutdown ||
        !p_SSL_free || !p_SHA256 || !p_RAND_bytes || !p_EVP_Digest || !p_EVP_md5) {
        fprintf(stderr, "[anytls-tiny] Error: Failed to resolve required OpenSSL symbols: %s\n", dlerror());
        return -1;
    }
    return 0;
}

/* SSL_get_error() misreports WANT_READ/WANT_WRITE if errors from another session are queued */
static void clear_ssl_errors(void) {
    if (p_ERR_clear_error) p_ERR_clear_error();
}

/*
 * Session pool: like the reference client, each connection gets an idle
 * session of its own (newest first) or a new one, and returns it to the pool
 * when it closes. Idle sessions are closed after g_idle_timeout seconds.
 * Past g_max_sessions, connections share the least-loaded session.
 */
enum { SESS_FREE = 0, SESS_CONNECTING, SESS_HANDSHAKE, SESS_READY };

typedef struct {
    SSL *ssl;
    int fd;
    uint8_t state;
    uint8_t broken;         /* torn down at the end of the current loop pass */
    uint8_t rx_kick;        /* frames may be waiting without a POLLIN */
    uint8_t rx_want_write;  /* SSL_read / SSL_connect asked for POLLOUT */
    uint8_t tx_want_write;
    uint8_t tx_hold;        /* cmdSettings waits for the first SYN, as in reference client */
    int peer_version;
    uint32_t seq;           /* creation order; the newest idle session is reused first */
    uint32_t next_sid;
    int nstreams, ndns;     /* TCP streams / DNS queries currently using the session */
    long wbuf_total;        /* downstream backlog of this session's streams */
    uint8_t *rx_buf;
    int rx_len;
    uint8_t *tx_buf;
    int tx_off, tx_len;
    int tx_inflight;        /* length of an SSL_write that must be retried */
    int server_idx;
    time_t created, ready_at, idle_since, last_rx, last_hb;
    time_t last_req_tx, tx_stuck_since;
    int pad_pkt;            /* next packet number of this session (0 is the auth) */
    int pad_rec[PAD_MAX_REC];/* TLS record sizes left in the packet being written */
    int pad_i, pad_n;
} session_t;

/* Stream tracking */
typedef struct {
    uint32_t stream_id;   /* 0 until cmdSYN has been sent */
    int client_fd;
    session_t *sess;      /* NULL until the stream is opened upstream */
    uint8_t is_redir;
    uint8_t socks_state;  /* 0: auth, 1: req, 2: connected */
    uint8_t remote_fin;   /* server closed the stream; close once wbuf drains */
    time_t last_active;
    /* Downstream data the LAN client could not accept yet */
    uint8_t *wbuf;
    int wlen, woff, wcap;
    time_t wprogress;
} stream_t;

typedef struct {
    uint32_t stream_id;   /* 0 = slot free */
    session_t *sess;
    struct sockaddr_in client_addr;
    time_t expire;
    uint8_t *rbuf;        /* reassembly of a reply split across PSH frames */
    int rlen;
} dns_req_t;

static session_t g_sessions[MAX_SESSIONS];
static uint32_t  g_session_seq = 0;
static session_t *g_dns_sess = NULL;  /* DNS queries share one session */
static stream_t  g_streams[MAX_STREAMS];
static dns_req_t g_dns_reqs[MAX_DNS_REQS];
static int       g_dns_active = 0;

static SSL_CTX *g_ssl_ctx = NULL;
static int      g_backoff = 0;
static time_t   g_next_connect = 0;
static time_t   g_last_fail = 0;
#define MAX_SERVERS 32

typedef struct {
    char host[128];
    int port;
    char sni[128];
    struct sockaddr_in addr;
    time_t resolved_at;
} server_entry_t;

static server_entry_t g_servers[MAX_SERVERS];
static int g_num_servers = 0;
static int g_current_server_idx = 0;
static int g_consecutive_fails = 0;

static void add_server(const char *host, int port, const char *sni) {
    if (g_num_servers >= MAX_SERVERS || !host || !host[0]) return;
    server_entry_t *s = &g_servers[g_num_servers++];
    memset(s, 0, sizeof(*s));
    strncpy(s->host, host, sizeof(s->host) - 1);
    s->port = (port > 0) ? port : 443;
    if (sni && sni[0]) {
        strncpy(s->sni, sni, sizeof(s->sni) - 1);
    } else {
        strncpy(s->sni, host, sizeof(s->sni) - 1);
    }
}

static void parse_and_add_server(const char *arg, int default_port, const char *default_sni) {
    char buf[256];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *host = buf;
    int port = default_port;
    char sni[128] = "";

    char *first_colon = strchr(host, ':');
    if (first_colon) {
        *first_colon = '\0';
        char *rest = first_colon + 1;
        char *second_colon = strchr(rest, ':');
        if (second_colon) {
            *second_colon = '\0';
            strncpy(sni, second_colon + 1, sizeof(sni) - 1);
        }
        port = atoi(rest);
    }
    if (sni[0] == '\0') {
        if (default_sni && default_sni[0]) {
            strncpy(sni, default_sni, sizeof(sni) - 1);
        } else {
            strncpy(sni, host, sizeof(sni) - 1);
        }
    }
    add_server(host, port, sni);
}

static int session_live(const session_t *s);

static void failover_next_server(const char *reason) {
    if (g_num_servers <= 0) return;
    int old_idx = g_current_server_idx;
    if (g_num_servers > 1) {
        g_current_server_idx = (g_current_server_idx + 1) % g_num_servers;
    }
    printf("[anytls-tiny] Failover (%s): switched to [%d/%d] %s:%d (SNI: %s)\n",
           reason, g_current_server_idx + 1, g_num_servers,
           g_servers[g_current_server_idx].host,
           g_servers[g_current_server_idx].port,
           g_servers[g_current_server_idx].sni);
    fflush(stdout);
    g_servers[g_current_server_idx].resolved_at = 0;
    g_servers[old_idx].resolved_at = 0;

    /* Tear down remaining zombie sessions on the failed server */
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i].server_idx == old_idx && session_live(&g_sessions[i])) {
            g_sessions[i].broken = 1;
        }
    }
    if (g_dns_sess && g_dns_sess->server_idx == old_idx) g_dns_sess = NULL;
}

static uint8_t g_client_rx_buf[CLIENT_READ_SIZE];
static long    g_wbuf_total = 0;

static char g_password[256] = "";
static char g_bind_addr[64] = "0.0.0.0";
static int  g_socks_port = 1080;
static int  g_redir_port = 1100;
static int  g_dns_port = 5353;
static int  g_dns_fd = -1;
static int  g_max_sessions = 8;
static int  g_idle_timeout = 60;
static int  g_min_idle = 1;
/* SOCKS5-style address of the DNS resolver reached through the tunnel */
static uint8_t g_dns_target[7] = { 0x01, 8, 8, 8, 8, 0, 53 };

/* AnyTLS padding scheme; the server can replace it with cmdUpdatePaddingScheme */
static const char g_default_scheme[] =
    "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
    "3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
static char g_pad_scheme[2048];
static char g_pad_md5[33];
static int  g_pad_stop = 0;

static int queue_frame(session_t *s, uint8_t cmd, uint32_t stream_id, const uint8_t *data, uint16_t len);

/* Value of "key=" in the scheme's key=value lines, or NULL */
static const char *scheme_get(const char *s, const char *key) {
    size_t kl = strlen(key);
    while (s) {
        if (!strncmp(s, key, kl) && s[kl] == '=') return s + kl + 1;
        s = strchr(s, '\n');
        if (s) s++;
    }
    return NULL;
}

static int pad_set_scheme(const char *s, int len) {
    char tmp[sizeof(g_pad_scheme)];
    uint8_t md[16];
    unsigned int mdlen;
    if (len <= 0 || len >= (int)sizeof(tmp)) return -1;
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    const char *stop = scheme_get(tmp, "stop");
    if (!stop || *stop < '0' || *stop > '9' || !p_EVP_Digest(tmp, len, md, &mdlen, p_EVP_md5(), NULL))
        return -1;
    memcpy(g_pad_scheme, tmp, len + 1);
    g_pad_stop = atoi(stop);
    for (int i = 0; i < 16; i++) sprintf(g_pad_md5 + 2 * i, "%02x", md[i]);
    return 0;
}

/* Record sizes the scheme gives packet pkt, sampled from "a-b" ranges; -1 is a check mark */
static int pad_sizes(int pkt, int *out) {
    char key[12];
    snprintf(key, sizeof(key), "%d", pkt);
    const char *s = scheme_get(g_pad_scheme, key);
    int n = 0;
    while (s && n < PAD_MAX_REC - 1) {
        char *e;
        long lo = strtol(s, &e, 10), hi;
        if (*s == 'c') {
            out[n++] = -1;
        } else if (e != s && *e == '-') {
            hi = strtol(e + 1, &e, 10);
            if (lo > hi) { long t = lo; lo = hi; hi = t; }
            if (lo > 0) {
                uint32_t r = 0;
                p_RAND_bytes((unsigned char *)&r, sizeof(r));
                if (hi > lo) lo += r % (hi - lo);
                out[n++] = lo > PAD_MAX_SIZE ? PAD_MAX_SIZE : lo;
            }
        }
        s = strpbrk(s, ",\n");
        if (!s || *s++ == '\n') break;
    }
    return n;
}

/*
 * Plan the next packet: everything queued now goes out as TLS records of the
 * sizes the scheme asks for, with cmdWaste frames appended to fill them.
 * Mirrors writeConn() in anytls-go's session.go.
 */
static void pad_plan(session_t *s) {
    int sz[PAD_MAX_REC];
    int n = pad_sizes(s->pad_pkt++, sz);
    int remain = s->tx_len - s->tx_off;
    s->pad_i = s->pad_n = 0;
    for (int k = 0; k < n; k++) {
        int l = sz[k], rec = remain;
        if (l < 0) {
            if (!remain) break;
            continue;
        }
        if (remain > l) {
            rec = l;
        } else {
            int pad = remain ? l - remain - FRAME_HDR : l;
            if (pad > 0) {
                if (s->tx_len + FRAME_HDR + pad > TX_BUF_SIZE) break;
                uint8_t *p = s->tx_buf + s->tx_len;
                memset(p, 0, FRAME_HDR + pad); /* cmdWaste, stream 0, zero data */
                p[5] = (pad >> 8) & 0xFF;
                p[6] = pad & 0xFF;
                s->tx_len += FRAME_HDR + pad;
                rec += FRAME_HDR + pad;
            }
        }
        remain -= rec < remain ? rec : remain;
        s->pad_rec[s->pad_n++] = rec;
    }
    if (remain) s->pad_rec[s->pad_n++] = remain;
}

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void set_tcp_nodelay(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static int session_live(const session_t *s) {
    return s->state != SESS_FREE && !s->broken;
}

static int tx_pending(const session_t *s) {
    return s->tx_len - s->tx_off;
}

/* Write as much of the session's TX buffer as the socket accepts without blocking. */
static void flush_tx(session_t *s) {
    while (s->state == SESS_READY && !s->broken && !s->tx_hold && s->tx_off < s->tx_len) {
        int len;
        if (s->pad_pkt == 0) {
            /* Packet 0 is only the Auth header (34 + pad0 bytes) */
            int pad0 = (s->tx_buf[32] << 8) | s->tx_buf[33];
            int alen = 34 + pad0;
            len = s->tx_inflight ? s->tx_inflight : alen - s->tx_off;
        } else {
            if (!s->pad_n && !s->tx_inflight && s->pad_pkt < g_pad_stop) pad_plan(s);
            /* A retried SSL_write must repeat the exact same buffer and length */
            len = s->tx_inflight ? s->tx_inflight : s->pad_n ? s->pad_rec[s->pad_i] : s->tx_len - s->tx_off;
        }

        clear_ssl_errors();
        int n = p_SSL_write(s->ssl, s->tx_buf + s->tx_off, len);
        if (n <= 0) {
            int err = p_SSL_get_error(s->ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                s->tx_inflight = len;
                s->tx_want_write = (err == SSL_ERROR_WANT_WRITE);
                return;
            }
            fprintf(stderr, "[anytls-tiny] Session %u: upstream write failed (err=%d)\n", s->seq, err);
            s->broken = 1;
            return;
        }
        s->tx_inflight = 0;
        s->tx_off += n;

        if (s->pad_pkt == 0) {
            int pad0 = (s->tx_buf[32] << 8) | s->tx_buf[33];
            int alen = 34 + pad0;
            if (s->tx_off == alen) {
                /* Packet 0 sent! Shift remainder (cmdSettings + any queued frames) to front */
                memmove(s->tx_buf, s->tx_buf + alen, s->tx_len - alen);
                s->tx_len -= alen;
                s->tx_off = 0;
                s->pad_pkt = 1;
                s->pad_i = s->pad_n = 0;
                if (s->nstreams + s->ndns == 0) {
                    s->tx_hold = 1;
                    break;
                }
            }
        } else if (s->pad_n && (s->pad_rec[s->pad_i] -= n) == 0 && ++s->pad_i == s->pad_n) {
            s->pad_n = 0;
        }
    }
    s->tx_want_write = 0;
    if (s->tx_off == s->tx_len) {
        s->tx_off = s->tx_len = 0;
    }
}

static void tx_compact(session_t *s) {
    if (s->tx_off > 0 && !s->tx_inflight) {
        memmove(s->tx_buf, s->tx_buf + s->tx_off, s->tx_len - s->tx_off);
        s->tx_len -= s->tx_off;
        s->tx_off = 0;
    }
}

static int tx_reserve(session_t *s, int need) {
    if (!s->tx_buf && !(s->tx_buf = malloc(TX_BUF_SIZE))) return -1;
    if (s->tx_len + need <= TX_BUF_SIZE) return 0;
    flush_tx(s);
    tx_compact(s);
    /* Still full: the uplink is congested, wait for it to drain */
    for (int tries = 0; s->tx_len + need > TX_BUF_SIZE; tries++) {
        if (s->state != SESS_READY) return -1;
        if (s->broken || tries >= 10) {
            s->broken = 1;
            return -1;
        }
        struct pollfd pfd = { .fd = s->fd, .events = s->tx_want_write ? POLLOUT : POLLIN };
        poll(&pfd, 1, 1000);
        flush_tx(s);
        tx_compact(s);
    }
    return 0;
}

/*
 * Frames are batched in the session's TX buffer and flushed once per
 * event-loop pass, so small control frames share TLS records with data
 * instead of each costing their own record and TCP segment. Frames queued
 * while the session is still connecting go out right after the handshake.
 */
static int queue_frame(session_t *s, uint8_t cmd, uint32_t stream_id, const uint8_t *data, uint16_t len) {
    if (!session_live(s)) return -1;
    if (tx_reserve(s, FRAME_HDR + len) < 0) return -1;

    uint8_t *p = s->tx_buf + s->tx_len;
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
    s->tx_len += FRAME_HDR + len;
    return 0;
}

static void session_unref(session_t *s, int dns) {
    if (dns) s->ndns--;
    else s->nstreams--;
    if (s->nstreams + s->ndns == 0) s->idle_since = time(NULL);
}

static void bump_backoff(time_t now) {
    g_consecutive_fails++;
    g_last_fail = now;
    /* Try all configured servers before delaying connection attempts */
    if (g_consecutive_fails >= g_num_servers) {
        g_backoff = g_backoff ? (g_backoff * 2 > MAX_BACKOFF ? MAX_BACKOFF : g_backoff * 2) : 1;
        g_next_connect = now + g_backoff;
    } else {
        g_next_connect = now;
    }
}

static int resolve_server(server_entry_t *srv, time_t now) {
    if (srv->resolved_at && now - srv->resolved_at < RESOLVE_TTL) return 0;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", srv->port);

    if (getaddrinfo(srv->host, port_str, &hints, &res) != 0 || !res) {
        fprintf(stderr, "[anytls-tiny] Failed to resolve %s\n", srv->host);
        return -1;
    }
    memcpy(&srv->addr, res->ai_addr, sizeof(srv->addr));
    freeaddrinfo(res);
    srv->resolved_at = now;
    return 0;
}

static void session_handshake(session_t *s) {
    clear_ssl_errors();
    int r = p_SSL_connect(s->ssl);
    if (r == 1) {
        s->state = SESS_READY;
        s->rx_want_write = 0;
        s->ready_at = s->last_rx = s->last_hb = time(NULL);
        g_consecutive_fails = 0;
        g_backoff = 0;
        server_entry_t *srv = &g_servers[s->server_idx];
        printf("[anytls-tiny] Session %u: connected to [%d/%d] %s:%d! TLS handshake done, auth sent\n",
               s->seq, s->server_idx + 1, g_num_servers, srv->host, srv->port);
        fflush(stdout);
        flush_tx(s);
        return;
    }
    int err = p_SSL_get_error(s->ssl, r);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        s->rx_want_write = (err == SSL_ERROR_WANT_WRITE);
        return;
    }
    fprintf(stderr, "[anytls-tiny] Session %u: SSL_connect failed (err=%d)\n", s->seq, err);
    s->broken = 1;
    if (s->server_idx == g_current_server_idx) {
        failover_next_server("handshake failed");
    }
}

static void session_start_tls(session_t *s) {
    s->ssl = p_SSL_new(g_ssl_ctx);
    if (!s->ssl) {
        s->broken = 1;
        return;
    }
    p_SSL_set_fd(s->ssl, s->fd);
    server_entry_t *srv = &g_servers[s->server_idx];
    p_SSL_ctrl(s->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, srv->sni);
    /* RELEASE_BUFFERS lets idle sessions give OpenSSL's record buffers back */
    p_SSL_ctrl(s->ssl, SSL_CTRL_MODE, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
               SSL_MODE_RELEASE_BUFFERS, NULL);

    /* ALPN: h2, http/1.1 */
    static const unsigned char alpn[] = { 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    p_SSL_set_alpn_protos(s->ssl, alpn, sizeof(alpn));

    s->state = SESS_HANDSHAKE;
    session_handshake(s);
}

/* The non-blocking connect() finished (or failed) */
static void session_connected(session_t *s) {
    int err = 0;
    socklen_t elen = sizeof(err);
    if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0 || err) {
        fprintf(stderr, "[anytls-tiny] Session %u: connect error: %s\n", s->seq, strerror(err ? err : errno));
        s->broken = 1;
        if (s->server_idx == g_current_server_idx) {
            failover_next_server("connect error");
        }
        return;
    }
    session_start_tls(s);
}

static void session_free(session_t *s, const char *why) {
    time_t now = time(NULL);
    if (s->broken) {
        /* A session that fails to come up, or dies right after (e.g. wrong password), backs off */
        if (s->state != SESS_READY || now - s->ready_at < 10) bump_backoff(now);
        if (s->server_idx >= 0 && s->server_idx < g_num_servers) {
            g_servers[s->server_idx].resolved_at = 0; /* the server's address may have changed */
        }
    }
    printf("[anytls-tiny] Session %u closed (%s, %d stream(s))\n", s->seq, why, s->nstreams);
    fflush(stdout);

    if (s->ssl) {
        if (s->state == SESS_READY && !s->broken) p_SSL_shutdown(s->ssl);
        p_SSL_free(s->ssl);
    }
    if (s->fd >= 0) close(s->fd);

    /* Streams can't move to another session: the server only knows them here */
    for (int i = 0; i < MAX_STREAMS; i++) {
        stream_t *st = &g_streams[i];
        if (st->client_fd > 0 && st->sess == s) {
            close(st->client_fd);
            g_wbuf_total -= st->wlen - st->woff;
            free(st->wbuf);
            memset(st, 0, sizeof(*st));
            st->client_fd = -1;
        }
    }
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        dns_req_t *d = &g_dns_reqs[i];
        if (d->stream_id && d->sess == s) {
            free(d->rbuf);
            memset(d, 0, sizeof(*d));
            g_dns_active--;
        }
    }
    if (g_dns_sess == s) g_dns_sess = NULL;

    free(s->rx_buf);
    free(s->tx_buf);
    memset(s, 0, sizeof(*s));
    s->fd = -1;
}

static int can_create_session(time_t now) {
    int live = 0, pending = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!session_live(&g_sessions[i])) continue;
        live++;
        if (g_sessions[i].state != SESS_READY) pending++;
    }
    if (live >= g_max_sessions || now < g_next_connect) return 0;
    /* While the server keeps failing, probe it with one connection at a time */
    return !(g_backoff && pending);
}

/* Start a non-blocking connect; the handshake is driven from the event loop */
static session_t *session_create(time_t now) {
    if (g_num_servers == 0) return NULL;
    session_t *s = NULL;
    for (int i = 0; i < MAX_SESSIONS && !s; i++) {
        if (g_sessions[i].state == SESS_FREE) s = &g_sessions[i];
    }
    if (!s) return NULL;

    server_entry_t *srv = &g_servers[g_current_server_idx];
    if (resolve_server(srv, now) < 0) {
        bump_backoff(now);
        failover_next_server("resolve failed");
        return NULL;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    set_nonblock(fd);
    set_tcp_nodelay(fd);

    /* Detect silently dropped connections (NAT timeouts, dead servers) */
    int one = 1, idle = 30, intvl = 10, cnt = 3;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));

    memset(s, 0, sizeof(*s));
    s->fd = fd;
    s->state = SESS_CONNECTING;
    s->seq = ++g_session_seq;
    s->server_idx = g_current_server_idx;
    s->next_sid = 1;
    s->peer_version = 2; /* Default to v2 to enable active heartbeats */
    s->created = s->idle_since = now;

    printf("[anytls-tiny] Session %u: connecting to [%d/%d] %s:%d (SNI: %s)\n",
           s->seq, g_current_server_idx + 1, g_num_servers, srv->host, srv->port, srv->sni);
    fflush(stdout);

    /* 1. Packet 0: SHA256(password) + uint16 padding0 length + padding0 zero bytes, sent on its own */
    int sz[PAD_MAX_REC];
    int pad0 = pad_sizes(0, sz) > 0 && sz[0] > 0 ? sz[0] : 0;
    int alen = 34 + pad0;
    if (tx_reserve(s, alen) < 0) {
        s->broken = 1;
        session_free(s, "out of memory");
        return NULL;
    }
    p_SHA256((const unsigned char *)g_password, strlen(g_password), s->tx_buf);
    s->tx_buf[32] = (pad0 >> 8) & 0xFF;
    s->tx_buf[33] = pad0 & 0xFF;
    memset(s->tx_buf + 34, 0, pad0);
    s->tx_len = alen;
    s->tx_off = 0;
    s->tx_hold = 0;
    s->pad_pkt = 0;
    s->pad_i = s->pad_n = 0;

    /* 2. cmdSettings is queued right after auth; both will share packet 1 with the first SYN */
    char settings[80];
    int slen = snprintf(settings, sizeof(settings), "v=2\nclient=anytls/0.0.1\npadding-md5=%s\n", g_pad_md5);
    queue_frame(s, CMD_SETTINGS, 0, (const uint8_t *)settings, slen);

    if (connect(fd, (struct sockaddr *)&srv->addr, sizeof(srv->addr)) == 0) {
        session_start_tls(s);
    } else if (errno != EINPROGRESS) {
        fprintf(stderr, "[anytls-tiny] Session %u: connect error: %s\n", s->seq, strerror(errno));
        s->broken = 1;
        bump_backoff(now);
        failover_next_server("connect immediate error");
    }
    if (s->broken) {
        session_free(s, "connect failed");
        return NULL;
    }
    return s;
}

/*
 * Pick a session for a new stream: the newest idle one (preferring sessions
 * that are already up and not carrying DNS), else a new one, else the
 * least-loaded live session.
 */
static session_t *acquire_session(time_t now) {
    session_t *idle = NULL, *least = NULL;
    int idle_rank = -1, least_load = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (!session_live(s)) continue;
        int load = s->nstreams + s->ndns;
        if (load == 0) {
            int rank = ((s->state == SESS_READY) << 1) | (s != g_dns_sess);
            if (rank > idle_rank || (rank == idle_rank && s->seq > idle->seq)) {
                idle = s;
                idle_rank = rank;
            }
        }
        if (!least || load < least_load ||
            (load == least_load && s->state == SESS_READY && least->state != SESS_READY)) {
            least = s;
            least_load = load;
        }
    }
    if (idle) return idle;
    if (can_create_session(now)) {
        session_t *s = session_create(now);
        if (s) return s;
    }
    return least;
}

static stream_t *find_stream_by_id(session_t *s, uint32_t sid) {
    if (sid == 0) return NULL;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0 && g_streams[i].sess == s && g_streams[i].stream_id == sid)
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
            g_streams[i].last_active = time(NULL);
            return &g_streams[i];
        }
    }
    return NULL;
}

static void wbuf_account(stream_t *st, long delta) {
    g_wbuf_total += delta;
    if (st->sess) st->sess->wbuf_total += delta;
}

/* Bind the stream to a session and send cmdSYN + target address; IDs are assigned in SYN order */
static int open_remote_stream(stream_t *st, const uint8_t *addr, int addr_len) {
    time_t now = time(NULL);
    session_t *s = acquire_session(now);
    if (!s) return -1;
    st->sess = s;
    st->last_active = now;
    s->nstreams++;
    s->wbuf_total += st->wlen - st->woff;
    st->stream_id = s->next_sid;
    s->next_sid += 2; /* Client stream IDs are odd */
    if (queue_frame(s, CMD_SYN, st->stream_id, NULL, 0) < 0) return -1;
    if (queue_frame(s, CMD_PSH, st->stream_id, addr, addr_len) < 0) return -1;
    s->last_req_tx = now;
    if (s->tx_hold) {
        s->tx_hold = 0;
        flush_tx(s);
    }
    return 0;
}

static void close_stream(stream_t *st) {
    if (!st || st->client_fd <= 0) return;
    session_t *s = st->sess;
    /* Per spec, a stream closed by the server is not answered with FIN */
    if (s && st->stream_id && !st->remote_fin) {
        queue_frame(s, CMD_FIN, st->stream_id, NULL, 0);
    }
    close(st->client_fd);
    wbuf_account(st, -(long)(st->wlen - st->woff));
    if (s) session_unref(s, 0);
    free(st->wbuf);
    memset(st, 0, sizeof(*st));
    st->client_fd = -1;
}

/* Deliver downstream data to a LAN client, buffering whatever it can't take yet */
static int stream_write(stream_t *st, const uint8_t *data, int len) {
    st->last_active = time(NULL);
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
    wbuf_account(st, len);
    return 0;
}

static void stream_flush(stream_t *st) {
    st->last_active = time(NULL);
    while (st->woff < st->wlen) {
        int n = send(st->client_fd, st->wbuf + st->woff, st->wlen - st->woff, MSG_NOSIGNAL);
        if (n > 0) {
            st->woff += n;
            wbuf_account(st, -n);
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

/*
 * Backpressure: stop reading a session while its LAN clients are too far
 * behind. Only that session pauses; the others keep flowing.
 */
static int rx_paused(const session_t *s) {
    if (s->wbuf_total <= WBUF_STREAM_MAX) return 0;
    if (g_wbuf_total > WBUF_TOTAL_MAX) return 1;
    for (int i = 0; i < MAX_STREAMS; i++) {
        if (g_streams[i].client_fd > 0 && g_streams[i].sess == s &&
            g_streams[i].wlen - g_streams[i].woff > WBUF_STREAM_MAX)
            return 1;
    }
    return 0;
}

static dns_req_t *find_dns_req(session_t *s, uint32_t sid) {
    if (!g_dns_active || sid == 0) return NULL;
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (g_dns_reqs[i].stream_id == sid && g_dns_reqs[i].sess == s) return &g_dns_reqs[i];
    }
    return NULL;
}

static void release_dns_req(dns_req_t *d, int send_fin) {
    if (!d->stream_id) return;
    if (send_fin) queue_frame(d->sess, CMD_FIN, d->stream_id, NULL, 0);
    session_unref(d->sess, 1);
    free(d->rbuf);
    memset(d, 0, sizeof(*d));
    g_dns_active--;
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

    if (open_remote_stream(st, saddr, saddr_len) < 0) {
        resp[1] = 0x01; /* general failure: no session to the server */
        stream_write(st, resp, 10);
        close_stream(st);
        return;
    }
    if (stream_write(st, resp, 10) < 0) {
        close_stream(st);
        return;
    }
    st->socks_state = 2;

    /* Forward any early data the client sent along with the request */
    int rest = n - 3 - saddr_len;
    if (rest > 0 && queue_frame(st->sess, CMD_PSH, st->stream_id, saddr + saddr_len, rest) < 0) {
        close_stream(st);
    }
}

static void handle_client_data(stream_t *st) {
    if (st->socks_state < 2) {
        handle_socks_handshake(st);
        return;
    }

    /* Bounded per pass so one bulk upload can't starve other clients */
    for (int k = 0; k < 4 && tx_pending(st->sess) < TX_HIGH_WATER; k++) {
        int n = recv(st->client_fd, g_client_rx_buf, sizeof(g_client_rx_buf), 0);
        if (n > 0) {
            st->last_active = time(NULL);
            if (st->sess) st->sess->last_req_tx = st->last_active;
            if (queue_frame(st->sess, CMD_PSH, st->stream_id, g_client_rx_buf, n) < 0) {
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

    dns_req_t *d = NULL;
    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (!g_dns_reqs[i].stream_id) {
            d = &g_dns_reqs[i];
            break;
        }
    }
    if (!d) return;

    /* Queries share one session; they move off it when a TCP stream lands
     * there, but only to an idle or new session, not round the busy ones */
    time_t now = time(NULL);
    session_t *s = g_dns_sess;
    if (s && !session_live(s)) s = NULL;
    if (!s || s->nstreams > 0) {
        session_t *n = acquire_session(now);
        if (n && (!s || n->nstreams == 0)) s = n;
    }
    g_dns_sess = s;
    if (!s) return;

    d->sess = s;
    s->ndns++;
    d->stream_id = s->next_sid;
    s->next_sid += 2;
    d->client_addr = cli;
    d->expire = now + DNS_TIMEOUT;
    g_dns_active++;

    /* One stream per query to the configured resolver, query sent with 2-byte length prefix */
    buf[0] = (n >> 8) & 0xFF;
    buf[1] = n & 0xFF;
    s->last_req_tx = now;
    if (queue_frame(s, CMD_SYN, d->stream_id, NULL, 0) < 0 ||
        queue_frame(s, CMD_PSH, d->stream_id, g_dns_target, sizeof(g_dns_target)) < 0 ||
        queue_frame(s, CMD_PSH, d->stream_id, buf, 2 + n) < 0) {
        release_dns_req(d, 0);
    }
    if (s->tx_hold) {
        s->tx_hold = 0;
        flush_tx(s);
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

static void handle_frame(session_t *s, uint8_t cmd, uint32_t sid, const uint8_t *data, int len) {
    dns_req_t *d;
    stream_t *st;

    switch (cmd) {
    case CMD_PSH:
        if ((d = find_dns_req(s, sid))) {
            handle_dns_data(d, data, len);
        } else if ((st = find_stream_by_id(s, sid)) && !st->remote_fin) {
            if (stream_write(st, data, len) < 0) close_stream(st);
        }
        break;
    case CMD_FIN:
        if ((d = find_dns_req(s, sid))) release_dns_req(d, 0);
        if ((st = find_stream_by_id(s, sid))) {
            st->remote_fin = 1;
            if (st->woff == st->wlen) close_stream(st);
        }
        break;
    case CMD_SYNACK:
        /* Non-empty payload: the server could not reach the target */
        if (len > 0) {
            printf("[anytls-tiny] Stream %u rejected by server: %.*s\n", sid, len > 200 ? 200 : len, (const char *)data);
            fflush(stdout);
            if ((d = find_dns_req(s, sid))) release_dns_req(d, 1);
            if ((st = find_stream_by_id(s, sid))) close_stream(st);
        }
        break;
    case CMD_HEART_REQ:
        queue_frame(s, CMD_HEART_RESP, sid, NULL, 0);
        break;
    case CMD_SERVER_SETTINGS:
        for (int i = 0; i + 2 < len; i++) {
            if ((i == 0 || data[i - 1] == '\n') && data[i] == 'v' && data[i + 1] == '=') {
                s->peer_version = atoi((const char *)data + i + 2);
                break;
            }
        }
        break;
    case CMD_UPDATE_PADDING:
        if (pad_set_scheme((const char *)data, len) == 0) {
            printf("[anytls-tiny] Padding scheme updated by server (md5 %s)\n", g_pad_md5);
            fflush(stdout);
        }
        break;
    case CMD_ALERT:
        fprintf(stderr, "[anytls-tiny] Alert from server: %.*s\n", len > 200 ? 200 : len, (const char *)data);
        s->broken = 1;
        break;
    default:
        /* cmdWaste, cmdHeartResponse: nothing to do */
        break;
    }
}

/* Parse all complete frames in the RX buffer; returns -1 if parsing had to stop early */
static int parse_rx_frames(session_t *s) {
    int off = 0, ret = 0;
    while (s->rx_len - off >= FRAME_HDR) {
        if (rx_paused(s)) { ret = -1; break; }
        const uint8_t *h = s->rx_buf + off;
        uint32_t sid = ((uint32_t)h[1] << 24) | ((uint32_t)h[2] << 16) |
                       ((uint32_t)h[3] << 8)  | (uint32_t)h[4];
        int flen = (h[5] << 8) | h[6];
        if (s->rx_len - off < FRAME_HDR + flen) break;

        handle_frame(s, h[0], sid, h + FRAME_HDR, flen);
        off += FRAME_HDR + flen;
        if (s->broken) return -1;
    }
    if (off > 0) {
        memmove(s->rx_buf, s->rx_buf + off, s->rx_len - off);
        s->rx_len -= off;
    }
    return ret;
}

static void handle_upstream_data(session_t *s) {
    s->rx_kick = 0;
    s->rx_want_write = 0;
    if (!s->rx_buf && !(s->rx_buf = malloc(RX_BUF_SIZE))) {
        s->broken = 1;
        return;
    }
    /* Drain several TLS records per wakeup instead of one per poll() */
    for (int iter = 0; iter < 16; iter++) {
        if (parse_rx_frames(s) < 0) {
            if (!s->broken) s->rx_kick = 1;
            return;
        }
        /* After parsing only a partial frame (< RX_BUF_SIZE) remains, so there is always room */
        clear_ssl_errors();
        int n = p_SSL_read(s->ssl, s->rx_buf + s->rx_len, RX_BUF_SIZE - s->rx_len);
        if (n <= 0) {
            int err = p_SSL_get_error(s->ssl, n);
            if (err == SSL_ERROR_WANT_READ) return;
            if (err == SSL_ERROR_WANT_WRITE) { s->rx_want_write = 1; return; }
            printf("[anytls-tiny] Session %u: upstream disconnected (err=%d)\n", s->seq, err);
            fflush(stdout);
            s->broken = 1;
            return;
        }
        s->rx_len += n;
        s->last_rx = time(NULL);
    }
    s->rx_kick = 1;
}

/* Close idle sessions past the timeout, keeping the newest g_min_idle of them */
static void expire_idle_sessions(time_t now) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (s->state != SESS_READY || s->broken || s->nstreams + s->ndns > 0) continue;
        if (now - s->idle_since < g_idle_timeout) continue;
        int newer = 0;
        for (int j = 0; j < MAX_SESSIONS; j++) {
            session_t *o = &g_sessions[j];
            if (o->state == SESS_READY && !o->broken && o->nstreams + o->ndns == 0 && o->seq > s->seq)
                newer++;
        }
        if (newer >= g_min_idle) session_free(s, "idle");
    }
}

/* Once-a-second housekeeping: heartbeats, dead-session detection, timeouts, idle pool */
static void periodic_tick(time_t now) {
    static time_t last_idle_check = 0;
    int live = 0;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        session_t *s = &g_sessions[i];
        if (!session_live(s)) continue;
        live++;

        if (s->state != SESS_READY) {
            if (now - s->created >= CONNECT_TIMEOUT) {
                fprintf(stderr, "[anytls-tiny] Session %u: connect/handshake timed out\n", s->seq);
                s->broken = 1;
                if (s->server_idx == g_current_server_idx) {
                    failover_next_server("connect/handshake timeout");
                }
            }
            continue;
        }

        /* Only a session that came up after the last failure and stays up resets the backoff */
        if (g_backoff && s->ready_at >= g_last_fail && now - s->ready_at >= 10) {
            g_backoff = 0;
            g_consecutive_fails = 0;
        }

        if (rx_paused(s)) s->last_rx = now; /* unread data is waiting in the kernel, the session is alive */

        if (s->peer_version >= 2 && !s->tx_hold) {
            if (now - s->last_rx >= HEARTBEAT_IDLE && now - s->last_hb >= HEARTBEAT_IDLE) {
                queue_frame(s, CMD_HEART_REQ, 0, NULL, 0);
                s->last_hb = now;
                flush_tx(s);
            }
        }

        /* Detect dead session when an active request was sent but never answered */
        if (s->last_req_tx > s->last_rx && now - s->last_req_tx >= 12) {
            printf("[anytls-tiny] Session %u: request timed out (no reply for %ds)\n",
                   s->seq, (int)(now - s->last_req_tx));
            fflush(stdout);
            s->broken = 1;
            if (s->server_idx == g_current_server_idx) {
                failover_next_server("request timeout");
            }
            continue;
        }

        /* Detect stuck uplink where socket buffer cannot be drained */
        if (tx_pending(s) > 0) {
            if (!s->tx_stuck_since) s->tx_stuck_since = now;
            else if (now - s->tx_stuck_since >= 12) {
                printf("[anytls-tiny] Session %u: uplink stuck for %ds\n",
                       s->seq, (int)(now - s->tx_stuck_since));
                fflush(stdout);
                s->broken = 1;
                if (s->server_idx == g_current_server_idx) {
                    failover_next_server("uplink stuck");
                }
                continue;
            }
        } else {
            s->tx_stuck_since = 0;
        }

        /* Idle sessions give their buffers back */
        if (s->nstreams + s->ndns == 0) {
            if (s->rx_buf && s->rx_len == 0 && !s->rx_kick) {
                free(s->rx_buf);
                s->rx_buf = NULL;
            }
            if (s->tx_buf && s->tx_len == 0) {
                free(s->tx_buf);
                s->tx_buf = NULL;
            }
        }
    }

    for (int i = 0; i < MAX_DNS_REQS; i++) {
        if (g_dns_reqs[i].stream_id && now >= g_dns_reqs[i].expire) {
            session_t *ds = g_dns_reqs[i].sess;
            if (ds && session_live(ds)) {
                printf("[anytls-tiny] DNS query timed out on session %u\n", ds->seq);
                fflush(stdout);
                ds->broken = 1;
                if (ds->server_idx == g_current_server_idx) {
                    failover_next_server("DNS timeout");
                }
            }
            release_dns_req(&g_dns_reqs[i], 1);
        }
    }

    /* Drop clients that stopped reading or idle connections */
    for (int i = 0; i < MAX_STREAMS; i++) {
        stream_t *st = &g_streams[i];
        if (st->client_fd <= 0) continue;
        int pending = st->wlen - st->woff;
        if (pending > 0) {
            if ((pending > WBUF_STREAM_MAX && now - st->wprogress >= STALL_TIMEOUT) ||
                now - st->wprogress >= IDLE_WRITE_TIMEOUT) {
                close_stream(st);
            }
        } else if (st->socks_state < 2) {
            if (now - st->last_active >= STREAM_HANDSHAKE_TIMEOUT) {
                close_stream(st);
            }
        } else if (now - st->last_active >= STREAM_IDLE_TIMEOUT) {
            close_stream(st);
        }
    }

    if (now - last_idle_check >= IDLE_CHECK_INTERVAL) {
        last_idle_check = now;
        expire_idle_sessions(now);
    }

    /* Keep a session warm (or keep retrying) while the pool is empty */
    if (live == 0 && g_min_idle > 0 && now >= g_next_connect) session_create(now);
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
    fprintf(stderr, "smallerAnyTLS - Ultra-lightweight AnyTLS v2 Client with Multi-Server Pool\n\n");
    fprintf(stderr, "Usage: %s -s <host[:port[:sni]]> [-s ...] -k <password> [options]\n\n", prog);
    fprintf(stderr, "Required options:\n");
    fprintf(stderr, "  -s <server>     Upstream AnyTLS server address (host[:port[:sni]], repeatable)\n");
    fprintf(stderr, "  -k <password>   AnyTLS authentication password or UUID\n");
    fprintf(stderr, "  -p <port>       Default upstream port (default: 443)\n");
    fprintf(stderr, "  -h <sni>        Default TLS SNI hostname\n\n");
    fprintf(stderr, "Optional:\n");
    fprintf(stderr, "  -l <port>       Local SOCKS5 proxy port (default: 1080, 0 = off)\n");
    fprintf(stderr, "  -r <port>       Transparent redirect port (SO_ORIGINAL_DST, default: 1100, 0 = off)\n");
    fprintf(stderr, "  -u <port>       DNS-over-TCP UDP listening port (default: 5353, 0 = off)\n");
    fprintf(stderr, "  -n <ip[:port]>  DNS resolver reached through the tunnel (default: 8.8.8.8:53)\n");
    fprintf(stderr, "  -b <ip>         Listen address for SOCKS5 and DNS (default: 0.0.0.0)\n");
    fprintf(stderr, "  -m <n>          Max TLS sessions to the server (1-%d, default: 8)\n", MAX_SESSIONS);
    fprintf(stderr, "  -i <seconds>    Close sessions idle for this long (default: 60)\n");
    fprintf(stderr, "  -w <n>          Idle sessions kept open past the timeout (default: 1)\n");
    fprintf(stderr, "  -d              Run as background daemon\n");
}

int main(int argc, char **argv) {
    int opt, daemonize = 0;
    char cli_host[128] = "";
    int cli_port = 443;
    char cli_sni[128] = "";

    while ((opt = getopt(argc, argv, "s:p:k:h:l:r:u:n:b:m:i:w:d")) != -1) {
        switch (opt) {
            case 's':
                if (strchr(optarg, ':')) {
                    parse_and_add_server(optarg, cli_port, cli_sni);
                } else {
                    strncpy(cli_host, optarg, sizeof(cli_host)-1);
                }
                break;
            case 'p': cli_port = atoi(optarg); break;
            case 'k': strncpy(g_password, optarg, sizeof(g_password)-1); break;
            case 'h': strncpy(cli_sni, optarg, sizeof(cli_sni)-1); break;
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
            case 'm': g_max_sessions = atoi(optarg); break;
            case 'i': g_idle_timeout = atoi(optarg); break;
            case 'w': g_min_idle = atoi(optarg); break;
            case 'd': daemonize = 1; break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (g_num_servers == 0 && cli_host[0] != '\0') {
        add_server(cli_host, cli_port, cli_sni[0] ? cli_sni : cli_host);
    }

    if (g_num_servers == 0 || g_password[0] == '\0') {
        fprintf(stderr, "[anytls-tiny] Error: At least one server (-s) and password (-k) are required.\n\n");
        print_usage(argv[0]);
        return 1;
    }
    if (g_max_sessions < 1 || g_max_sessions > MAX_SESSIONS || g_idle_timeout < 1 || g_min_idle < 0) {
        fprintf(stderr, "[anytls-tiny] Error: -m must be 1-%d, -i at least 1, -w at least 0.\n", MAX_SESSIONS);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    if (init_openssl() < 0) {
        return 1;
    }
    pad_set_scheme(g_default_scheme, sizeof(g_default_scheme) - 1);

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

    printf("[anytls-tiny] Started! Servers: %d, SOCKS5:%d, Redir:%d, DNS-UDP:%d, max sessions:%d\n",
           g_num_servers, g_socks_port, g_redir_port, g_dns_port, g_max_sessions);
    for (int i = 0; i < g_num_servers; i++) {
        printf("  [%d] %s:%d (SNI: %s)\n", i + 1, g_servers[i].host, g_servers[i].port, g_servers[i].sni);
    }
    fflush(stdout);

    for (int i = 0; i < MAX_SESSIONS; i++) g_sessions[i].fd = -1;
    time_t last_tick = time(NULL);
    if (g_min_idle > 0) session_create(last_tick);

    enum { NFIXED = 3, NFDS = NFIXED + MAX_SESSIONS + MAX_STREAMS };
    struct pollfd fds[NFDS];
    int fd_map[NFDS];
    uint32_t fd_seq[NFDS];

    while (1) {
        /* Fixed slots 0-2; poll() ignores entries whose fd is -1 */
        fds[0].fd = socks_fd; fds[0].events = POLLIN;
        fds[1].fd = redir_fd; fds[1].events = POLLIN;
        fds[2].fd = g_dns_fd; fds[2].events = POLLIN;
        int nfds = NFIXED, kick = 0;

        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = &g_sessions[i];
            if (!session_live(s)) continue;
            short ev;
            if (s->state == SESS_CONNECTING) {
                ev = POLLOUT;
            } else if (s->state == SESS_HANDSHAKE) {
                ev = s->rx_want_write ? POLLOUT : POLLIN;
            } else {
                int paused = rx_paused(s);
                ev = (paused ? 0 : POLLIN) | (s->tx_want_write || s->rx_want_write ? POLLOUT : 0);
                if (s->rx_kick && !paused) kick = 1;
            }
            fd_map[nfds] = i;
            fd_seq[nfds] = s->seq;
            fds[nfds].fd = s->fd;
            fds[nfds].events = ev;
            nfds++;
        }
        int sess_end = nfds;

        for (int i = 0; i < MAX_STREAMS; i++) {
            stream_t *st = &g_streams[i];
            if (st->client_fd <= 0) continue;
            short ev = 0;
            if (!st->remote_fin && (!st->sess || tx_pending(st->sess) < TX_HIGH_WATER)) ev |= POLLIN;
            if (st->woff < st->wlen) ev |= POLLOUT;
            fd_map[nfds] = i;
            fds[nfds].fd = st->client_fd;
            fds[nfds].events = ev;
            nfds++;
        }

        int ret = poll(fds, nfds, kick ? 0 : 1000);
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

        for (int j = NFIXED; j < sess_end; j++) {
            session_t *s = &g_sessions[fd_map[j]];
            /* The slot may have been freed (and reused) earlier in this pass */
            if (!session_live(s) || s->seq != fd_seq[j]) continue;
            short re = fds[j].revents;
            if (s->state == SESS_CONNECTING) {
                if (re) session_connected(s);
            } else if (s->state == SESS_HANDSHAKE) {
                if (re) session_handshake(s);
            } else {
                int paused = rx_paused(s);
                if (re & POLLOUT) flush_tx(s);
                if (paused && (re & (POLLERR | POLLHUP))) {
                    s->broken = 1;
                } else if ((re & (POLLIN | POLLERR | POLLHUP)) || (s->rx_kick && !paused) ||
                           (s->rx_want_write && (re & POLLOUT))) {
                    handle_upstream_data(s);
                }
            }
        }

        if (ret > 0) {
            for (int j = sess_end; j < nfds; j++) {
                stream_t *st = &g_streams[fd_map[j]];
                /* The slot may have been closed earlier in this pass */
                if (!fds[j].revents || st->client_fd != fds[j].fd) continue;
                if (fds[j].revents & POLLOUT) stream_flush(st);
                if (st->client_fd != fds[j].fd) continue;
                if (fds[j].revents & POLLIN) handle_client_data(st);
                else if (fds[j].revents & (POLLERR | POLLHUP)) close_stream(st);
            }
        }

        for (int i = 0; i < MAX_SESSIONS; i++) {
            session_t *s = &g_sessions[i];
            if (s->state == SESS_FREE) continue;
            flush_tx(s);
            if (s->broken) session_free(s, "error");
        }
    }

    return 0;
}

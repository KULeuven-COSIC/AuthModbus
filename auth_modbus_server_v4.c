/*
Build:
  gcc -O2 -Wall -Wextra auth_modbus_server_v4.c -o auth_modbus_server_v4 -lmodbus -lssl -lcrypto

Run:
  ./auth_modbus_server_v4
*/

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <modbus/modbus.h>

#define LISTEN_PORT 1502
#define BACKLOG 16

#define MAGIC "AMOD"
#define MAGIC_LEN 4

#define VER_1 0x01

#define TYPE_AUTH_INIT  0x01
#define TYPE_AUTH_CHAL  0x02
#define TYPE_AUTH_PROOF 0x03
#define TYPE_DATA_REQ   0x10
#define TYPE_DATA_RSP   0x11
#define TYPE_AUTH_FAIL  0x7F

#define NONCE_LEN 16
#define SESSION_ID_LEN 8
#define TAG_LEN 32

#define INNER_MAX 260
#define DATA_HDR_LEN (MAGIC_LEN + 1 + 1 + SESSION_ID_LEN + 8 + 2)

static volatile int g_running = 1;

static void on_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

/* ---------- helpers ---------- */
static int recv_exact(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r == 0) return 0; // closed
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)r;
    }
    return 1;
}

static int send_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, buf + off, n - off, 0);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

// Read one complete Modbus TCP ADU (MBAP total = 6 + LEN)
static int recv_modbus_tcp_adu(int fd, uint8_t *buf, size_t buf_cap, int *out_len) {
    int rc = recv_exact(fd, buf, 6);
    if (rc <= 0) return rc;

    uint16_t len_net;
    memcpy(&len_net, buf + 4, 2);
    uint16_t len = ntohs(len_net);

    size_t total = 6u + (size_t)len;
    if (total > buf_cap) return -1;

    rc = recv_exact(fd, buf + 6, len);
    if (rc <= 0) return rc;

    *out_len = (int)total;
    return 1;
}

/* ---------- crypto ---------- */
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t out[TAG_LEN]) {
    unsigned int out_len = 0;
    unsigned char *p = HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, out, &out_len);
    if (!p || out_len != TAG_LEN) return -1;
    return 0;
}

static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t v = 0;
    for (size_t i = 0; i < n; i++) v |= (a[i] ^ b[i]);
    return (v == 0);
}

/* ---------- logging ---------- */
static void reject_reason(const char *why) {
    fprintf(stderr, "[-] REJECT %s\n", why);
}

static void accept_log(uint64_t seq, uint8_t fc, uint16_t addr, uint16_t nb) {
    fprintf(stderr,
            "[+] accepted requests: seq=%" PRIu64 ", fc=0x%02x, addr=%u, nb=%u\n",
            seq, fc, addr, nb);
}

/* ---------- auth state (per connection) ---------- */
typedef struct {
    uint8_t client_nonce[NONCE_LEN];
    uint8_t server_nonce[NONCE_LEN];
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t session_key[TAG_LEN];
    uint64_t last_seq;
    int authed;
} auth_state_t;

static const uint8_t DEMO_PSK[] = "replace-with-strong-psk-bytes";

static int derive_session_key(auth_state_t *st) {
    uint8_t msg[7 + NONCE_LEN + NONCE_LEN + SESSION_ID_LEN];
    memcpy(msg, "session", 7);
    memcpy(msg + 7, st->client_nonce, NONCE_LEN);
    memcpy(msg + 7 + NONCE_LEN, st->server_nonce, NONCE_LEN);
    memcpy(msg + 7 + NONCE_LEN + NONCE_LEN, st->session_id, SESSION_ID_LEN);
    return hmac_sha256(DEMO_PSK, sizeof(DEMO_PSK) - 1, msg, sizeof(msg), st->session_key);
}

/* ---------- handshake messages ---------- */
static int send_auth_fail(int fd) {
    uint8_t msg[MAGIC_LEN + 1 + 1];
    memcpy(msg, MAGIC, MAGIC_LEN);
    msg[4] = VER_1;
    msg[5] = TYPE_AUTH_FAIL;
    return send_all(fd, msg, sizeof(msg));
}

static int recv_auth_init(int fd, auth_state_t *st) {
    uint8_t hdr[MAGIC_LEN + 1 + 1];
    int rc = recv_exact(fd, hdr, sizeof(hdr));
    if (rc <= 0) return rc;
    if (memcmp(hdr, MAGIC, MAGIC_LEN) != 0) return -1;
    if (hdr[4] != VER_1 || hdr[5] != TYPE_AUTH_INIT) return -1;
    rc = recv_exact(fd, st->client_nonce, NONCE_LEN);
    return rc;
}

static int send_auth_challenge(int fd, auth_state_t *st) {
    uint8_t msg[MAGIC_LEN + 1 + 1 + SESSION_ID_LEN + NONCE_LEN];
    memcpy(msg, MAGIC, MAGIC_LEN);
    msg[4] = VER_1;
    msg[5] = TYPE_AUTH_CHAL;

    if (RAND_bytes(st->session_id, SESSION_ID_LEN) != 1) return -1;
    if (RAND_bytes(st->server_nonce, NONCE_LEN) != 1) return -1;

    memcpy(msg + 6, st->session_id, SESSION_ID_LEN);
    memcpy(msg + 6 + SESSION_ID_LEN, st->server_nonce, NONCE_LEN);
    return send_all(fd, msg, sizeof(msg));
}

static int recv_auth_proof_and_verify(int fd, auth_state_t *st) {
    uint8_t hdr[MAGIC_LEN + 1 + 1];
    int rc = recv_exact(fd, hdr, sizeof(hdr));
    if (rc <= 0) return rc;
    if (memcmp(hdr, MAGIC, MAGIC_LEN) != 0) return -1;
    if (hdr[4] != VER_1 || hdr[5] != TYPE_AUTH_PROOF) return -1;

    uint8_t tag_recv[TAG_LEN];
    rc = recv_exact(fd, tag_recv, TAG_LEN);
    if (rc <= 0) return rc;

    uint8_t msg[NONCE_LEN + NONCE_LEN + SESSION_ID_LEN];
    memcpy(msg, st->client_nonce, NONCE_LEN);
    memcpy(msg + NONCE_LEN, st->server_nonce, NONCE_LEN);
    memcpy(msg + NONCE_LEN + NONCE_LEN, st->session_id, SESSION_ID_LEN);

    uint8_t tag_calc[TAG_LEN];
    if (hmac_sha256(DEMO_PSK, sizeof(DEMO_PSK) - 1, msg, sizeof(msg), tag_calc) != 0)
        return -1;

    if (!ct_memeq(tag_recv, tag_calc, TAG_LEN)) return -1;
    if (derive_session_key(st) != 0) return -1;

    st->authed = 1;
    st->last_seq = 0;
    return 1;
}

/* ---------- DATA envelope ---------- */
typedef struct {
    uint8_t  ver;
    uint8_t  type;
    uint8_t  session_id[SESSION_ID_LEN];
    uint64_t seq;
    uint16_t inner_len;
} data_hdr_t;

static int recv_data_envelope(int fd, data_hdr_t *out_hdr,
                              uint8_t inner[INNER_MAX], uint8_t tag[TAG_LEN]) {
    uint8_t hdr_raw[DATA_HDR_LEN];
    int rc = recv_exact(fd, hdr_raw, sizeof(hdr_raw));
    if (rc <= 0) return rc;

    if (memcmp(hdr_raw, MAGIC, MAGIC_LEN) != 0) return -1;

    out_hdr->ver  = hdr_raw[4];
    out_hdr->type = hdr_raw[5];
    if (out_hdr->ver != VER_1) return -1;

    memcpy(out_hdr->session_id, hdr_raw + 6, SESSION_ID_LEN);

    uint64_t seq_net;
    memcpy(&seq_net, hdr_raw + 6 + SESSION_ID_LEN, 8);
    out_hdr->seq = be64toh(seq_net);

    uint16_t len_net;
    memcpy(&len_net, hdr_raw + 6 + SESSION_ID_LEN + 8, 2);
    out_hdr->inner_len = ntohs(len_net);
    if (out_hdr->inner_len > INNER_MAX) return -1;

    rc = recv_exact(fd, inner, out_hdr->inner_len);
    if (rc <= 0) return rc;

    rc = recv_exact(fd, tag, TAG_LEN);
    return rc;
}

static int compute_data_tag(const auth_state_t *st,
                            const data_hdr_t *h,
                            const uint8_t *inner,
                            uint8_t out[TAG_LEN]) {
    uint8_t tmp_hdr[1 + 1 + SESSION_ID_LEN + 8 + 2];
    size_t off = 0;

    tmp_hdr[off++] = h->ver;
    tmp_hdr[off++] = h->type;
    memcpy(tmp_hdr + off, h->session_id, SESSION_ID_LEN); off += SESSION_ID_LEN;

    uint64_t seq_net = htobe64(h->seq);
    memcpy(tmp_hdr + off, &seq_net, 8); off += 8;

    uint16_t len_net = htons(h->inner_len);
    memcpy(tmp_hdr + off, &len_net, 2); off += 2;

    size_t msg_len = sizeof(tmp_hdr) + h->inner_len;
    uint8_t *msg = (uint8_t*)malloc(msg_len);
    if (!msg) return -1;

    memcpy(msg, tmp_hdr, sizeof(tmp_hdr));
    memcpy(msg + sizeof(tmp_hdr), inner, h->inner_len);

    int rc = hmac_sha256(st->session_key, TAG_LEN, msg, msg_len, out);
    free(msg);
    return rc;
}

static int send_data_envelope(int fd, const auth_state_t *st,
                              uint8_t type, uint64_t seq,
                              const uint8_t session_id[SESSION_ID_LEN],
                              const uint8_t *inner, uint16_t inner_len) {
    data_hdr_t h;
    h.ver = VER_1;
    h.type = type;
    memcpy(h.session_id, session_id, SESSION_ID_LEN);
    h.seq = seq;
    h.inner_len = inner_len;

    uint8_t tag[TAG_LEN];
    if (compute_data_tag(st, &h, inner, tag) != 0) return -1;

    size_t total = DATA_HDR_LEN + inner_len + TAG_LEN;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return -1;

    memcpy(buf, MAGIC, MAGIC_LEN);
    buf[4] = h.ver;
    buf[5] = h.type;
    memcpy(buf + 6, h.session_id, SESSION_ID_LEN);

    uint64_t seq_net = htobe64(h.seq);
    memcpy(buf + 6 + SESSION_ID_LEN, &seq_net, 8);

    uint16_t len_net = htons(h.inner_len);
    memcpy(buf + 6 + SESSION_ID_LEN + 8, &len_net, 2);

    memcpy(buf + DATA_HDR_LEN, inner, inner_len);
    memcpy(buf + DATA_HDR_LEN + inner_len, tag, TAG_LEN);

    int rc = send_all(fd, buf, total);
    free(buf);
    return rc;
}

/* ---------- global persistent mapping ---------- */
static modbus_mapping_t *g_mapping = NULL;

static void init_baseline_mapping(modbus_mapping_t *m) {
    // Holding registers baseline demo: 0x1000 + i
    for (int i = 0; i < 200; i++) m->tab_registers[i] = (uint16_t)(0x1000u + (uint16_t)i);
    m->tab_registers[10] = 0xBEEF; // canary / demo register

    fprintf(stderr, "[*] Initial holding registers (0..11):\n");
    for (int i = 0; i <= 11; i++)
        fprintf(stderr, "    R[%d] = 0x%04x\n", i, m->tab_registers[i]);
}

/* ---------- parse request meta for logging ---------- */
static int parse_modbus_request_meta(const uint8_t *adu, int adu_len,
                                     uint8_t *out_fc,
                                     uint16_t *out_addr,
                                     uint16_t *out_nb) {
    // PDU starts at index 7 in Modbus/TCP ADU
    if (adu_len < 12) return -1;
    uint8_t fc = adu[7];
    uint16_t addr = (uint16_t)((adu[8] << 8) | adu[9]);

    uint16_t nb = 0;
    if (fc == 0x03 || fc == 0x04) {
        nb = (uint16_t)((adu[10] << 8) | adu[11]);
    } else if (fc == 0x06) {
        nb = 1;
    } else if (fc == 0x10) {
        nb = (uint16_t)((adu[10] << 8) | adu[11]);
    } else {
        nb = 0; // unknown; still log fc
    }

    *out_fc = fc;
    *out_addr = addr;
    *out_nb = nb;
    return 0;
}

/* ---------- libmodbus response capture via socketpair ---------- */
static int capture_modbus_reply(modbus_t *ctx,
                                int trap_read_fd,
                                const uint8_t *req_adu, int req_len,
                                modbus_mapping_t *mapping,
                                uint8_t rsp[INNER_MAX], int *rsp_len_out) {
    int rc = modbus_reply(ctx, req_adu, req_len, mapping);
    if (rc == -1) return -1;

    int got = 0;
    rc = recv_modbus_tcp_adu(trap_read_fd, rsp, INNER_MAX, &got);
    if (rc <= 0) return -1;

    *rsp_len_out = got;
    return 0;
}

/* ---------- TCP server ---------- */
static int make_listen_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(fd); return -1; }
    if (listen(fd, BACKLOG) < 0) { close(fd); return -1; }
    return fd;
}

static void handle_client(int cfd) {
    auth_state_t st;
    memset(&st, 0, sizeof(st));

    // --- handshake ---
    int rc = recv_auth_init(cfd, &st);
    if (rc <= 0) { reject_reason("handshake: missing/invalid AUTH_INIT"); close(cfd); return; }

    if (send_auth_challenge(cfd, &st) != 0) {
        reject_reason("handshake: failed to send AUTH_CHAL");
        close(cfd);
        return;
    }

    rc = recv_auth_proof_and_verify(cfd, &st);
    if (rc <= 0) {
        reject_reason("handshake: AUTH_PROOF failed (bad PSK/tag)");
        send_auth_fail(cfd);
        close(cfd);
        return;
    }

    fprintf(stderr, "[+] client authed\n");

    // libmodbus ctx + socketpair trap (per connection)
    modbus_t *ctx = modbus_new_tcp("127.0.0.1", 1);
    if (!ctx) { close(cfd); return; }

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        modbus_free(ctx);
        close(cfd);
        return;
    }
    modbus_set_socket(ctx, sp[0]);

    // --- main loop ---
    while (g_running) {
        data_hdr_t h;
        uint8_t inner[INNER_MAX];
        uint8_t tag_recv[TAG_LEN];

        rc = recv_data_envelope(cfd, &h, inner, tag_recv);
        if (rc == 0) break;
        if (rc < 0) { reject_reason("bad envelope"); break; }

        if (h.type != TYPE_DATA_REQ) {
            fprintf(stderr, "[-] REJECT unexpected type=0x%02x\n", h.type);
            break;
        }

        if (!ct_memeq(h.session_id, st.session_id, SESSION_ID_LEN)) {
            reject_reason("bad session");
            break;
        }

        uint8_t tag_calc[TAG_LEN];
        if (compute_data_tag(&st, &h, inner, tag_calc) != 0) {
            reject_reason("hmac calc error");
            break;
        }
        if (!ct_memeq(tag_recv, tag_calc, TAG_LEN)) {
            reject_reason("HMAC FAIL");
            break;
        }

        if (h.seq <= st.last_seq) {
            fprintf(stderr, "[-] REJECT replay (seq=%" PRIu64 ", last=%" PRIu64 ")\n",
                    h.seq, st.last_seq);
            break;
        }

        // accepted => update last_seq and log meta
        st.last_seq = h.seq;

        uint8_t fc = 0;
        uint16_t addr = 0, nb = 0;
        if (parse_modbus_request_meta(inner, (int)h.inner_len, &fc, &addr, &nb) == 0)
            accept_log(h.seq, fc, addr, nb);
        else
            accept_log(h.seq, 0xFF, 0, 0);

        uint8_t rsp_inner[INNER_MAX];
        int rsp_len = 0;

        // Use persistent global mapping: writes persist across connections.
        if (capture_modbus_reply(ctx, sp[1], inner, (int)h.inner_len, g_mapping,
                                rsp_inner, &rsp_len) != 0) {
            reject_reason("modbus_reply failed");
            break;
        }

        if (send_data_envelope(cfd, &st, TYPE_DATA_RSP, h.seq, st.session_id,
                               rsp_inner, (uint16_t)rsp_len) != 0) {
            reject_reason("send response failed");
            break;
        }
    }

    close(sp[0]); close(sp[1]);
    modbus_close(ctx);
    modbus_free(ctx);
    close(cfd);
    fprintf(stderr, "[*] client disconnected\n");
}

int main(void) {
    signal(SIGINT, on_sigint);

    // Persistent mapping created ONCE (global state)
    g_mapping = modbus_mapping_new(500, 500, 500, 500);
    if (!g_mapping) {
        fprintf(stderr, "modbus_mapping_new failed\n");
        return 1;
    }
    init_baseline_mapping(g_mapping);

    int lfd = make_listen_socket(LISTEN_PORT);
    if (lfd < 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "[*] Auth-Modbus server listening on %d (persistent registers)\n", LISTEN_PORT);

    while (g_running) {
        struct sockaddr_in ca;
        socklen_t calen = sizeof(ca);
        int cfd = accept(lfd, (struct sockaddr *)&ca, &calen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        fprintf(stderr, "[+] client connected\n");
        handle_client(cfd);
    }

    close(lfd);
    modbus_mapping_free(g_mapping);
    g_mapping = NULL;
    return 0;
}

/*
Build:
  gcc -O2 -Wall -Wextra auth_modbus_client_v3.c -o auth_modbus_client_v3 -lmodbus -lssl -lcrypto

Usage (reads):
  ./auth_modbus_client <ip> <unit_id> <fc> <addr> <nb>
  ./auth_modbus_client <ip> <fc> <addr> <nb>            (unit_id defaults to 1)
  ./auth_modbus_client_v3 127.0.0.1 1 6 10 1 0x1234
  ./auth_modbus_client_v3 127.0.0.1 1 3 0 20

Usage (writes):
  ./auth_modbus_client <ip> <unit_id> 6  <addr> 1  <value>
  ./auth_modbus_client <ip> <unit_id> 16 <addr> <nb> <base>

fc: 3 (FC03), 4 (FC04), 6 (FC06), 16 (FC16)
*/

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <modbus/modbus.h>

#define AUTH_PORT 1502

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

static const uint8_t DEMO_PSK[] = "replace-with-strong-psk-bytes";

// ---------- helpers ----------
static int recv_exact(int fd, uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r == 0) return 0;
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

// Read one complete Modbus TCP ADU from a stream using MBAP length field.
// Total bytes = 6 + LEN (where LEN includes UnitID + PDU).
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

static uint16_t parse_u16(const char *s) {
    unsigned long v = strtoul(s, NULL, 0); // accepts decimal or 0x...
    return (uint16_t)(v & 0xFFFFu);
}

typedef struct {
    uint8_t client_nonce[NONCE_LEN];
    uint8_t server_nonce[NONCE_LEN];
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t session_key[TAG_LEN];
    uint64_t seq;
    int authed;
} auth_state_t;

static int derive_session_key(auth_state_t *st) {
    uint8_t msg[7 + NONCE_LEN + NONCE_LEN + SESSION_ID_LEN];
    memcpy(msg, "session", 7);
    memcpy(msg + 7, st->client_nonce, NONCE_LEN);
    memcpy(msg + 7 + NONCE_LEN, st->server_nonce, NONCE_LEN);
    memcpy(msg + 7 + NONCE_LEN + NONCE_LEN, st->session_id, SESSION_ID_LEN);
    return hmac_sha256(DEMO_PSK, sizeof(DEMO_PSK) - 1, msg, sizeof(msg), st->session_key);
}

// ---------- handshake ----------
static int auth_send_init(int fd, auth_state_t *st) {
    uint8_t hdr[MAGIC_LEN + 1 + 1];
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[4] = VER_1;
    hdr[5] = TYPE_AUTH_INIT;

    if (RAND_bytes(st->client_nonce, NONCE_LEN) != 1) return -1;
    if (send_all(fd, hdr, sizeof(hdr)) != 0) return -1;
    if (send_all(fd, st->client_nonce, NONCE_LEN) != 0) return -1;
    return 0;
}

static int auth_recv_challenge(int fd, auth_state_t *st) {
    uint8_t hdr[MAGIC_LEN + 1 + 1];
    int rc = recv_exact(fd, hdr, sizeof(hdr));
    if (rc <= 0) return rc;

    if (memcmp(hdr, MAGIC, MAGIC_LEN) != 0) return -1;
    if (hdr[4] != VER_1 || hdr[5] == TYPE_AUTH_FAIL) return -1;
    if (hdr[5] != TYPE_AUTH_CHAL) return -1;

    rc = recv_exact(fd, st->session_id, SESSION_ID_LEN);
    if (rc <= 0) return rc;
    rc = recv_exact(fd, st->server_nonce, NONCE_LEN);
    return rc;
}

static int auth_send_proof(int fd, auth_state_t *st) {
    uint8_t msg[NONCE_LEN + NONCE_LEN + SESSION_ID_LEN];
    memcpy(msg, st->client_nonce, NONCE_LEN);
    memcpy(msg + NONCE_LEN, st->server_nonce, NONCE_LEN);
    memcpy(msg + NONCE_LEN + NONCE_LEN, st->session_id, SESSION_ID_LEN);

    uint8_t tag[TAG_LEN];
    if (hmac_sha256(DEMO_PSK, sizeof(DEMO_PSK) - 1, msg, sizeof(msg), tag) != 0)
        return -1;

    uint8_t hdr[MAGIC_LEN + 1 + 1];
    memcpy(hdr, MAGIC, MAGIC_LEN);
    hdr[4] = VER_1;
    hdr[5] = TYPE_AUTH_PROOF;

    if (send_all(fd, hdr, sizeof(hdr)) != 0) return -1;
    if (send_all(fd, tag, TAG_LEN) != 0) return -1;

    if (derive_session_key(st) != 0) return -1;
    st->authed = 1;
    st->seq = 0;
    return 0;
}

// ---------- data envelope ----------
typedef struct {
    uint8_t ver;
    uint8_t type;
    uint8_t session_id[SESSION_ID_LEN];
    uint64_t seq;
    uint16_t inner_len;
} data_hdr_t;

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

static int recv_data_envelope(int fd,
                              data_hdr_t *out_hdr,
                              uint8_t inner[INNER_MAX],
                              uint8_t tag[TAG_LEN]) {
    uint8_t hdr_raw[DATA_HDR_LEN];
    int rc = recv_exact(fd, hdr_raw, sizeof(hdr_raw));
    if (rc <= 0) return rc;

    if (memcmp(hdr_raw, MAGIC, MAGIC_LEN) != 0) return -1;
    out_hdr->ver = hdr_raw[4];
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

// ---------- TCP connect ----------
static int connect_tcp(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }

    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) != 0) { close(fd); return -1; }
    return fd;
}

// ---------- libmodbus ADU capture ----------
static int build_inner_adu_with_libmodbus(modbus_t *ctx,
                                          int trap_read_fd,
                                          const uint8_t *raw_req, int raw_len,
                                          uint8_t inner[INNER_MAX], int *inner_len_out) {
    int rc = modbus_send_raw_request(ctx, raw_req, raw_len);
    if (rc == -1) return -1;

    int got = 0;
    rc = recv_modbus_tcp_adu(trap_read_fd, inner, INNER_MAX, &got);
    if (rc <= 0) return -1;

    *inner_len_out = got;
    return 0;
}

static int feed_inner_rsp_to_libmodbus_and_read(modbus_t *ctx,
                                                int trap_write_fd,
                                                uint8_t rsp_buf[INNER_MAX], int *rsp_len_out,
                                                const uint8_t *inner_rsp, int inner_len) {
    if (send_all(trap_write_fd, inner_rsp, (size_t)inner_len) != 0) return -1;

    int rc = modbus_receive_confirmation(ctx, rsp_buf);
    if (rc <= 0) return -1;

    *rsp_len_out = rc;
    return 0;
}

// Parse FC03/FC04 response registers from Modbus/TCP ADU
static int parse_fc3_fc4_registers(const uint8_t *adu, int adu_len,
                                   uint8_t expected_fc,
                                   uint16_t *out_regs, int max_regs) {
    if (adu_len < 9) return -1; // need MBAP + fc + bytecount

    uint8_t fc = adu[7]; // PDU starts at 7 (UnitID at 6, FC at 7)
    if (fc & 0x80) {
        if (adu_len < 9) return -1;
        fprintf(stderr, "Modbus exception: fc=0x%02x ex=0x%02x\n", fc, adu[8]);
        return -1;
    }
    if (fc != expected_fc) return -1;

    uint8_t byte_count = adu[8];
    if (9 + byte_count > adu_len) return -1;

    int reg_count = (int)(byte_count / 2);
    if (reg_count > max_regs) reg_count = max_regs;

    const uint8_t *p = &adu[9];
    for (int i = 0; i < reg_count; i++) {
        out_regs[i] = (uint16_t)((p[2*i] << 8) | p[2*i + 1]);
    }
    return reg_count;
}

// Parse write responses (FC06/FC16)
static int parse_write_ok(const uint8_t *adu, int adu_len, uint8_t expected_fc) {
    if (adu_len < 12) return -1;

    uint8_t fc = adu[7];
    if (fc & 0x80) {
        fprintf(stderr, "Modbus exception: fc=0x%02x ex=0x%02x\n", fc, adu[8]);
        return -1;
    }
    if (fc != expected_fc) return -1;

    uint16_t addr = (uint16_t)((adu[8] << 8) | adu[9]);
    uint16_t val_or_nb = (uint16_t)((adu[10] << 8) | adu[11]);

    if (expected_fc == 0x06) {
        printf("FC06 OK: addr=%u value=0x%04x (%u)\n", addr, val_or_nb, val_or_nb);
    } else {
        printf("FC16 OK: addr=%u nb=%u\n", addr, val_or_nb);
    }
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage:\n"
        "  Reads:\n"
        "    %s <ip> <unit> <fc> <addr> <nb>\n"
        "    %s <ip> <fc> <addr> <nb>        (unit defaults to 1)\n"
        "  Writes:\n"
        "    %s <ip> <unit> 6  <addr> 1  <value>\n"
        "    %s <ip> <unit> 16 <addr> <nb> <base>\n"
        "fc: 3, 4, 6, 16\n",
        p, p, p, p);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        usage(argv[0]);
        return 1;
    }

    const char *ip = argv[1];

    int unit_id = 1;
    int fc = 0, addr = 0, nb = 0;
    uint16_t value_or_base = 0;

    // Accepted layouts:
    //  A) ip fc addr nb                      (argc == 5)  -> read only
    //  B) ip unit fc addr nb [value/base]    (argc >= 6)
    if (argc == 5) {
        fc   = atoi(argv[2]);
        addr = atoi(argv[3]);
        nb   = atoi(argv[4]);
    } else {
        unit_id = atoi(argv[2]);
        fc      = atoi(argv[3]);
        addr    = atoi(argv[4]);
        nb      = atoi(argv[5]);
        if (fc == 6 || fc == 16) {
            if (argc < 7) {
                fprintf(stderr, "Missing value/base for write.\n");
                usage(argv[0]);
                return 1;
            }
            value_or_base = parse_u16(argv[6]);
        }
    }

    if (!(fc == 3 || fc == 4 || fc == 6 || fc == 16)) {
        fprintf(stderr, "Unsupported fc=%d (use 3,4,6,16)\n", fc);
        return 1;
    }

    if (fc == 6 && nb != 1) {
        // your raw request builder for FC06 ignores nb anyway, but keep the CLI clean
        nb = 1;
    }

    int fd = connect_tcp(ip, AUTH_PORT);
    if (fd < 0) { perror("connect"); return 1; }

    auth_state_t st;
    memset(&st, 0, sizeof(st));

    // --- handshake ---
    if (auth_send_init(fd, &st) != 0) { fprintf(stderr, "auth init failed\n"); return 1; }
    if (auth_recv_challenge(fd, &st) <= 0) { fprintf(stderr, "auth chal failed\n"); return 1; }
    if (auth_send_proof(fd, &st) != 0) { fprintf(stderr, "auth proof failed\n"); return 1; }
    fprintf(stderr, "[+] authed\n");

    // --- libmodbus context + socketpair trap ---
    modbus_t *ctx = modbus_new_tcp("127.0.0.1", 1);
    if (!ctx) { fprintf(stderr, "modbus_new_tcp failed\n"); return 1; }

    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
        perror("socketpair");
        return 1;
    }
    modbus_set_socket(ctx, sp[0]);
    modbus_set_slave(ctx, unit_id);

    // --- Build raw request (unit + PDU) ---
    uint8_t *raw_req = NULL;
    int raw_len = 0;

    if (fc == 3 || fc == 4) {
        // [unit][fc][addr_hi][addr_lo][nb_hi][nb_lo]
        raw_len = 6;
        raw_req = (uint8_t*)malloc((size_t)raw_len);
        raw_req[0] = (uint8_t)unit_id;
        raw_req[1] = (uint8_t)fc;
        raw_req[2] = (uint8_t)((addr >> 8) & 0xFF);
        raw_req[3] = (uint8_t)(addr & 0xFF);
        raw_req[4] = (uint8_t)((nb >> 8) & 0xFF);
        raw_req[5] = (uint8_t)(nb & 0xFF);
    } else if (fc == 6) {
        // [unit][0x06][addr_hi][addr_lo][val_hi][val_lo]
        raw_len = 6;
        raw_req = (uint8_t*)malloc((size_t)raw_len);
        raw_req[0] = (uint8_t)unit_id;
        raw_req[1] = 0x06;
        raw_req[2] = (uint8_t)((addr >> 8) & 0xFF);
        raw_req[3] = (uint8_t)(addr & 0xFF);
        raw_req[4] = (uint8_t)((value_or_base >> 8) & 0xFF);
        raw_req[5] = (uint8_t)(value_or_base & 0xFF);
    } else { // fc == 16
        // [unit][0x10][addr_hi][addr_lo][nb_hi][nb_lo][byte_count][data...]
        if (nb <= 0 || nb > 123) {
            fprintf(stderr, "Invalid nb for FC16 (1..123)\n");
            return 1;
        }
        raw_len = 7 + 2 * nb;
        raw_req = (uint8_t*)malloc((size_t)raw_len);
        raw_req[0] = (uint8_t)unit_id;
        raw_req[1] = 0x10;
        raw_req[2] = (uint8_t)((addr >> 8) & 0xFF);
        raw_req[3] = (uint8_t)(addr & 0xFF);
        raw_req[4] = (uint8_t)((nb >> 8) & 0xFF);
        raw_req[5] = (uint8_t)(nb & 0xFF);
        raw_req[6] = (uint8_t)(2 * nb);
        for (int i = 0; i < nb; i++) {
            uint16_t v = (uint16_t)(value_or_base + (uint16_t)i);
            raw_req[7 + 2*i]     = (uint8_t)((v >> 8) & 0xFF);
            raw_req[7 + 2*i + 1] = (uint8_t)(v & 0xFF);
        }
    }

    // --- Build inner ADU using libmodbus ---
    uint8_t inner_req[INNER_MAX];
    int inner_req_len = 0;
    if (build_inner_adu_with_libmodbus(ctx, sp[1], raw_req, raw_len, inner_req, &inner_req_len) != 0) {
        fprintf(stderr, "failed to build inner request\n");
        return 1;
    }
    free(raw_req);

    // --- Wrap & send authenticated request ---
    st.seq++;
    if (send_data_envelope(fd, &st, TYPE_DATA_REQ, st.seq, st.session_id,
                           inner_req, (uint16_t)inner_req_len) != 0) {
        fprintf(stderr, "send request failed\n");
        return 1;
    }

    // --- Receive authenticated response ---
    data_hdr_t h;
    uint8_t inner_rsp[INNER_MAX];
    uint8_t tag_recv[TAG_LEN];
    int rc = recv_data_envelope(fd, &h, inner_rsp, tag_recv);
    if (rc <= 0) { fprintf(stderr, "recv response failed\n"); return 1; }

    if (h.type != TYPE_DATA_RSP) { fprintf(stderr, "unexpected rsp type\n"); return 1; }
    if (!ct_memeq(h.session_id, st.session_id, SESSION_ID_LEN)) { fprintf(stderr, "bad session\n"); return 1; }
    if (h.seq != st.seq) { fprintf(stderr, "seq mismatch\n"); return 1; }

    uint8_t tag_calc[TAG_LEN];
    if (compute_data_tag(&st, &h, inner_rsp, tag_calc) != 0) { fprintf(stderr, "hmac calc failed\n"); return 1; }
    if (!ct_memeq(tag_recv, tag_calc, TAG_LEN)) { fprintf(stderr, "HMAC FAIL on response\n"); return 1; }

    // --- Feed inner response into libmodbus and read confirmation ---
    uint8_t rsp_buf[INNER_MAX];
    int rsp_len = 0;
    if (feed_inner_rsp_to_libmodbus_and_read(ctx, sp[1], rsp_buf, &rsp_len, inner_rsp, (int)h.inner_len) != 0) {
        fprintf(stderr, "libmodbus receive_confirmation failed\n");
        return 1;
    }

    // --- Print outputs ---
    if (fc == 3 || fc == 4) {
        uint16_t regs[125];
        int got = parse_fc3_fc4_registers(rsp_buf, rsp_len, (uint8_t)fc, regs, 125);
        if (got < 0) {
            fprintf(stderr, "failed to parse FC%d response\n", fc);
            return 1;
        }

        const char *label = (fc == 3) ? "Holding" : "Input";
        printf("FC%d (%s): Read %d registers starting at %d:\n", fc, label, got, addr);
        for (int i = 0; i < got; i++) {
            printf("  R[%d] = 0x%04x (%u)\n", addr + i, regs[i], regs[i]);
        }
    } else if (fc == 6) {
        if (parse_write_ok(rsp_buf, rsp_len, 0x06) != 0) {
            fprintf(stderr, "failed to parse FC06 response\n");
            return 1;
        }
    } else { // fc == 16
        if (parse_write_ok(rsp_buf, rsp_len, 0x10) != 0) {
            fprintf(stderr, "failed to parse FC16 response\n");
            return 1;
        }
    }

    close(sp[0]); close(sp[1]);
    modbus_close(ctx);
    modbus_free(ctx);
    close(fd);
    return 0;
}

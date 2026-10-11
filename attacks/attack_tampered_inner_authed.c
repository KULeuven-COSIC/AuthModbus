/*
Attack3
the attacker authenticates, sends one valid authenticated request, then sends a second 
request where the INNER Modbus ADU is tampered (e.g., FC03 → FC06 or address changed) but the MAC/tag is 
kept from the original. That guarantees the server reaches the integrity check and logs HMAC FAIL

Build:
  gcc -O2 -Wall -Wextra attack_tampered_inner_authed.c -o attack_tampered_inner_authed -lssl -lcrypto

Run:
  ./attack_tampered_inner_authed <server_ip> [unit] [addr] [nb]

Example:
  ./attack_tampered_inner_authed 127.0.0.1 1 0 4

Expected server logs (v4-style):
  [+] client connected
  [+] client authed
  [+] accepted requests: seq=1, fc=0x03, addr=0, nb=4
  [-] REJECT HMAC FAIL
*/

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

/* ---------- helpers ---------- */
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

static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len,
                       uint8_t out[TAG_LEN]) {
    unsigned int out_len = 0;
    unsigned char *p = HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, out, &out_len);
    if (!p || out_len != TAG_LEN) return -1;
    return 0;
}

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

/* ---------- state ---------- */
typedef struct {
    uint8_t client_nonce[NONCE_LEN];
    uint8_t server_nonce[NONCE_LEN];
    uint8_t session_id[SESSION_ID_LEN];
    uint8_t session_key[TAG_LEN];
} st_t;

static int derive_session_key(st_t *st) {
    uint8_t msg[7 + NONCE_LEN + NONCE_LEN + SESSION_ID_LEN];
    memcpy(msg, "session", 7);
    memcpy(msg + 7, st->client_nonce, NONCE_LEN);
    memcpy(msg + 7 + NONCE_LEN, st->server_nonce, NONCE_LEN);
    memcpy(msg + 7 + NONCE_LEN + NONCE_LEN, st->session_id, SESSION_ID_LEN);
    return hmac_sha256(DEMO_PSK, sizeof(DEMO_PSK) - 1, msg, sizeof(msg), st->session_key);
}

/* ---------- handshake ---------- */
static int auth_handshake(int fd, st_t *st) {
    // AUTH_INIT
    uint8_t init_hdr[MAGIC_LEN + 1 + 1];
    memcpy(init_hdr, MAGIC, MAGIC_LEN);
    init_hdr[4] = VER_1;
    init_hdr[5] = TYPE_AUTH_INIT;

    if (RAND_bytes(st->client_nonce, NONCE_LEN) != 1) return -1;
    if (send_all(fd, init_hdr, sizeof(init_hdr)) != 0) return -1;
    if (send_all(fd, st->client_nonce, NONCE_LEN) != 0) return -1;

    // AUTH_CHAL
    uint8_t chal_hdr[MAGIC_LEN + 1 + 1];
    int rc = recv_exact(fd, chal_hdr, sizeof(chal_hdr));
    if (rc <= 0) return -1;
    if (memcmp(chal_hdr, MAGIC, MAGIC_LEN) != 0) return -1;
    if (chal_hdr[4] != VER_1) return -1;
    if (chal_hdr[5] == TYPE_AUTH_FAIL) return -1;
    if (chal_hdr[5] != TYPE_AUTH_CHAL) return -1;

    rc = recv_exact(fd, st->session_id, SESSION_ID_LEN);
    if (rc <= 0) return -1;
    rc = recv_exact(fd, st->server_nonce, NONCE_LEN);
    if (rc <= 0) return -1;

    // AUTH_PROOF
    uint8_t proof_hdr[MAGIC_LEN + 1 + 1];
    memcpy(proof_hdr, MAGIC, MAGIC_LEN);
    proof_hdr[4] = VER_1;
    proof_hdr[5] = TYPE_AUTH_PROOF;

    uint8_t proof_msg[NONCE_LEN + NONCE_LEN + SESSION_ID_LEN];
    memcpy(proof_msg, st->client_nonce, NONCE_LEN);
    memcpy(proof_msg + NONCE_LEN, st->server_nonce, NONCE_LEN);
    memcpy(proof_msg + NONCE_LEN + NONCE_LEN, st->session_id, SESSION_ID_LEN);

    uint8_t proof_tag[TAG_LEN];
    if (hmac_sha256(DEMO_PSK, sizeof(DEMO_PSK) - 1, proof_msg, sizeof(proof_msg), proof_tag) != 0)
        return -1;

    if (send_all(fd, proof_hdr, sizeof(proof_hdr)) != 0) return -1;
    if (send_all(fd, proof_tag, TAG_LEN) != 0) return -1;

    if (derive_session_key(st) != 0) return -1;
    return 0;
}

/* ---------- inner Modbus/TCP ADU: FC03 Read Holding ---------- */
static int build_inner_fc3(uint8_t inner[INNER_MAX], uint16_t tid,
                           uint8_t unit, uint16_t addr, uint16_t nb, int *out_len) {
    uint8_t adu[12];
    adu[0] = (uint8_t)(tid >> 8); adu[1] = (uint8_t)(tid & 0xFF);
    adu[2] = 0x00; adu[3] = 0x00;
    adu[4] = 0x00; adu[5] = 0x06;
    adu[6] = unit;
    adu[7] = 0x03;
    adu[8] = (uint8_t)(addr >> 8); adu[9]  = (uint8_t)(addr & 0xFF);
    adu[10]= (uint8_t)(nb >> 8);   adu[11] = (uint8_t)(nb & 0xFF);

    memcpy(inner, adu, sizeof(adu));
    *out_len = (int)sizeof(adu);
    return 0;
}

/* ---------- compute tag for DATA message ---------- */
static int compute_data_tag(const st_t *st,
                            uint8_t ver, uint8_t type,
                            const uint8_t session_id[SESSION_ID_LEN],
                            uint64_t seq, uint16_t inner_len,
                            const uint8_t *inner,
                            uint8_t out[TAG_LEN]) {
    uint8_t tmp_hdr[1 + 1 + SESSION_ID_LEN + 8 + 2];
    size_t off = 0;

    tmp_hdr[off++] = ver;
    tmp_hdr[off++] = type;

    memcpy(tmp_hdr + off, session_id, SESSION_ID_LEN); off += SESSION_ID_LEN;

    uint64_t seq_net = htobe64(seq);
    memcpy(tmp_hdr + off, &seq_net, 8); off += 8;

    uint16_t len_net = htons(inner_len);
    memcpy(tmp_hdr + off, &len_net, 2); off += 2;

    size_t msg_len = sizeof(tmp_hdr) + inner_len;
    uint8_t *msg = (uint8_t*)malloc(msg_len);
    if (!msg) return -1;

    memcpy(msg, tmp_hdr, sizeof(tmp_hdr));
    memcpy(msg + sizeof(tmp_hdr), inner, inner_len);

    int rc = hmac_sha256(st->session_key, TAG_LEN, msg, msg_len, out);
    free(msg);
    return rc;
}

/* ---------- build DATA_REQ packet ---------- */
static int build_data_req_packet(const st_t *st,
                                 uint64_t seq,
                                 const uint8_t *inner, uint16_t inner_len,
                                 uint8_t **out_pkt, size_t *out_len) {
    size_t total = DATA_HDR_LEN + (size_t)inner_len + TAG_LEN;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return -1;

    memcpy(buf, MAGIC, MAGIC_LEN);
    buf[4] = VER_1;
    buf[5] = TYPE_DATA_REQ;
    memcpy(buf + 6, st->session_id, SESSION_ID_LEN);

    uint64_t seq_net = htobe64(seq);
    memcpy(buf + 6 + SESSION_ID_LEN, &seq_net, 8);

    uint16_t len_net = htons(inner_len);
    memcpy(buf + 6 + SESSION_ID_LEN + 8, &len_net, 2);

    memcpy(buf + DATA_HDR_LEN, inner, inner_len);

    uint8_t tag[TAG_LEN];
    if (compute_data_tag(st, VER_1, TYPE_DATA_REQ, st->session_id, seq, inner_len, inner, tag) != 0) {
        free(buf);
        return -1;
    }
    memcpy(buf + DATA_HDR_LEN + inner_len, tag, TAG_LEN);

    *out_pkt = buf;
    *out_len = total;
    return 0;
}

/* ---------- receive and discard one DATA_RSP ---------- */
static int recv_and_discard_data_rsp(int fd) {
    uint8_t hdr[DATA_HDR_LEN];
    int rc = recv_exact(fd, hdr, sizeof(hdr));
    if (rc <= 0) return rc;

    if (memcmp(hdr, MAGIC, MAGIC_LEN) != 0) return -1;
    if (hdr[4] != VER_1) return -1;
    if (hdr[5] != TYPE_DATA_RSP) return -1;

    uint16_t len_net;
    memcpy(&len_net, hdr + 6 + SESSION_ID_LEN + 8, 2);
    uint16_t inner_len = ntohs(len_net);
    if (inner_len > INNER_MAX) return -1;

    uint8_t inner[INNER_MAX];
    uint8_t tag[TAG_LEN];

    rc = recv_exact(fd, inner, inner_len);
    if (rc <= 0) return rc;

    rc = recv_exact(fd, tag, TAG_LEN);
    if (rc <= 0) return rc;

    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip> [unit] [addr] [nb]\n", argv[0]);
        return 1;
    }
    const char *ip = argv[1];
    int unit = (argc >= 3) ? atoi(argv[2]) : 1;
    int addr = (argc >= 4) ? atoi(argv[3]) : 0;
    int nb   = (argc >= 5) ? atoi(argv[4]) : 4;

    int fd = connect_tcp(ip, AUTH_PORT);
    if (fd < 0) { perror("connect"); return 1; }

    st_t st;
    memset(&st, 0, sizeof(st));
    if (auth_handshake(fd, &st) != 0) {
        fprintf(stderr, "[-] handshake failed\n");
        close(fd);
        return 1;
    }

    // Build a valid authenticated DATA_REQ (seq=1)
    uint8_t inner_ok[INNER_MAX];
    int inner_len_i = 0;
    build_inner_fc3(inner_ok, 1, (uint8_t)unit, (uint16_t)addr, (uint16_t)nb, &inner_len_i);

    uint8_t *pkt_ok = NULL;
    size_t pkt_ok_len = 0;
    if (build_data_req_packet(&st, 1, inner_ok, (uint16_t)inner_len_i, &pkt_ok, &pkt_ok_len) != 0) {
        fprintf(stderr, "[-] failed to build valid DATA_REQ\n");
        close(fd);
        return 1;
    }

    printf("[*] Sending valid authenticated DATA_REQ (seq=1)\n");
    if (send_all(fd, pkt_ok, pkt_ok_len) != 0) {
        fprintf(stderr, "[-] send failed\n");
        free(pkt_ok);
        close(fd);
        return 1;
    }

    if (recv_and_discard_data_rsp(fd) <= 0) {
        fprintf(stderr, "[-] did not receive DATA_RSP (server may have closed)\n");
        free(pkt_ok);
        close(fd);
        return 1;
    }
    printf("[*] Received DATA_RSP for seq=1\n");

    // Build a SECOND request where we tamper the inner ADU but KEEP the OLD tag (MITM model)
    // We do this by:
    //  - Copying pkt_ok entirely
    //  - Changing a byte inside INNER_ADU (e.g., function code 0x03 -> 0x06)
    //  - Reusing the same tag bytes (no recomputation)
    uint8_t *pkt_tamper = (uint8_t*)malloc(pkt_ok_len);
    if (!pkt_tamper) {
        free(pkt_ok);
        close(fd);
        return 1;
    }
    memcpy(pkt_tamper, pkt_ok, pkt_ok_len);

    // INNER_ADU starts at offset DATA_HDR_LEN in the envelope.
    // In a Modbus/TCP ADU, FC is at index 7 within the ADU, so:
    // envelope offset = DATA_HDR_LEN + 7
    size_t fc_off = (size_t)DATA_HDR_LEN + 7;
    printf("[*] Tampering INNER_ADU: FC03 -> FC06 (without updating HMAC)\n");
    pkt_tamper[fc_off] = 0x06; // change function code

    // Also (optional) tamper address bytes to make it more obvious:
    // Modbus address is at ADU indices 8..9
    size_t addr_off = (size_t)DATA_HDR_LEN + 8;
    pkt_tamper[addr_off + 0] = 0x00;
    pkt_tamper[addr_off + 1] = 0x0A; // addr=10

    // Note: seq remains 1 here. That's fine: the server should reject on HMAC first.
    printf("[*] Sending tampered authenticated DATA_REQ (expected: HMAC FAIL)\n");
    (void)send_all(fd, pkt_tamper, pkt_ok_len);

    free(pkt_tamper);
    free(pkt_ok);
    close(fd);
    return 0;
}

/* release.c — hybrid release-signing harness (Ed25519 + ML-DSA).
 *
 * Subcommands:
 *   genkey <scheme> <key_id> <keydir>
 *       scheme: Ed25519 | ML-DSA-44 | ML-DSA-65 | ML-DSA-87.
 *       Writes raw key files <keydir>/<key_id>.pk and .sk (runtime-generated
 *       keys only; never commit them). Prints lengths and a SHA-256
 *       fingerprint of the public key (first 16 hex chars) for logging.
 *   sign <artifact> <version> <classical_key_id> <keydir>
 *        <pq_scheme> <pq_key_id> <keydir> <manifest_out>
 *       Computes SHA-256 of the artifact, builds the canonical to-be-signed
 *       (TBS) string, signs it with Ed25519 AND with ML-DSA (pure ML-DSA,
 *       FIPS 204 §5.2), and writes a flat JSON hybrid release manifest.
 *   verify <manifest> <artifact> <state_file> <revocation_file>
 *       Recomputes the artifact digest, enforces the monotonic version
 *       (manifest version must exceed the installed version in state_file),
 *       rejects any key id present in revocation_file, applies the FIPS 204
 *       §3.6.2 length checks (pk/sig lengths per scheme), then verifies
 *       each signature independently against the recomputed TBS.
 *       On ACCEPT the state file is updated to the manifest version.
 *       Exit 0 = ACCEPT, 1 = REJECT, 2 = usage/internal error.
 *       Prints "VERDICT: ACCEPT|REJECT" and "REASON: ..." for drivers.
 *
 * The TBS string is the same bytes for both schemes:
 *   hybrid-release-manifest/1\n<sha256hex>\n<version>\n<size>\n
 *   <classical_key_id>\n<pq_key_id>\n<classical_scheme>\n<pq_scheme>\n
 *
 * Expected sizes (checked in code): FIPS 204 Table 2 for ML-DSA-44/65/87,
 * RFC 8032 §1 for Ed25519 (pk 32, sig 64).
 *
 * Compile: cc -O2 -I<liboqs include> release.c -L<liboqs lib> -loqs -lcrypto -o release
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

/* ---------- small utilities ---------- */

static int read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return -1; }
    uint8_t *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return -1; }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return -1; }
    fclose(f);
    buf[n] = 0;
    *out = buf; *out_len = (size_t)n;
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

static void sha256_hex(const uint8_t *data, size_t len, char out[65]) {
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(data, len, d);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) sprintf(out + 2 * i, "%02x", d[i]);
    out[64] = 0;
}

static char *b64_encode(const uint8_t *in, size_t len) {
    /* EVP_EncodeBlock output: 4*ceil(len/3) + NUL. */
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;
    EVP_EncodeBlock((unsigned char *)out, in, (int)len);
    return out;
}

static int b64_decode(const char *in, uint8_t **out, size_t *out_len) {
    size_t in_len = strlen(in);
    size_t cap = 3 * ((in_len + 3) / 4) + 1;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    int n = EVP_DecodeBlock(buf, (const unsigned char *)in, (int)in_len);
    if (n < 0) { free(buf); return -1; }
    /* EVP_DecodeBlock counts padding as bytes; strip '=' padding. */
    size_t pad = 0;
    while (in_len > 0 && in[in_len - 1] == '=') { pad++; in_len--; }
    *out = buf; *out_len = (size_t)n - pad;
    return 0;
}

/* Flat-JSON helpers: the manifest is flat, keys unique, values strings or numbers. */
static int json_get_string(const char *json, const char *key, char *out, size_t out_cap) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return -1;
    p++;
    const char *e = strchr(p, '"');
    if (!e) return -1;
    size_t n = (size_t)(e - p);
    if (n >= out_cap) return -1;
    memcpy(out, p, n);
    out[n] = 0;
    return 0;
}

static int json_get_u64(const char *json, const char *key, uint64_t *out) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    *out = strtoull(p + 1, NULL, 10);
    return 0;
}

/* ---------- scheme tables (FIPS 204 Table 2; RFC 8032 §1) ---------- */

typedef struct { const char *name; size_t sk, pk, sig; } SchemeSize;
static const SchemeSize MLDSA_SIZES[] = {
    { "ML-DSA-44", 2560, 1312, 2420 },
    { "ML-DSA-65", 4032, 1952, 3309 },
    { "ML-DSA-87", 4896, 2592, 4627 },
};
static const SchemeSize *mldsa_size(const char *name) {
    for (size_t i = 0; i < sizeof(MLDSA_SIZES) / sizeof(MLDSA_SIZES[0]); i++)
        if (strcmp(name, MLDSA_SIZES[i].name) == 0) return &MLDSA_SIZES[i];
    return NULL;
}
static int is_ed25519(const char *name) { return strcmp(name, "Ed25519") == 0; }

/* ---------- Ed25519 via OpenSSL EVP ---------- */

static int ed25519_keypair(uint8_t *pk, uint8_t *sk) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519", NULL);
    if (!k) return -1;
    size_t pk_len = 32, sk_len = 32;
    int rc = EVP_PKEY_get_raw_public_key(k, pk, &pk_len) == 1 &&
             EVP_PKEY_get_raw_private_key(k, sk, &sk_len) == 1 &&
             pk_len == 32 && sk_len == 32;
    EVP_PKEY_free(k);
    return rc ? 0 : -1;
}

static int ed25519_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                         uint8_t *sig, size_t *sig_len) {
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
    if (!k) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = -1;
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, k) == 1 &&
        EVP_DigestSign(ctx, sig, sig_len, msg, msg_len) == 1) rc = 0;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return rc;
}

static int ed25519_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len) {
    EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
    if (!k) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, k) == 1) &&
             (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return rc ? 0 : -1;
}

/* ---------- ML-DSA via liboqs ---------- */

static int mldsa_keypair(const char *alg, uint8_t *pk, uint8_t *sk) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    int rc = OQS_SIG_keypair(s, pk, sk) == OQS_SUCCESS ? 0 : -1;
    OQS_SIG_free(s);
    return rc;
}

static int mldsa_sign(const char *alg, const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                      uint8_t *sig, size_t *sig_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    int rc = OQS_SIG_sign(s, sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS ? 0 : -1;
    OQS_SIG_free(s);
    return rc;
}

static int mldsa_verify(const char *alg, const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len) {
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    int rc = OQS_SIG_verify(s, msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS ? 0 : -1;
    OQS_SIG_free(s);
    return rc;
}

/* Generic sign/verify dispatch used by sign/verify subcommands. */
static int sign_with(const char *scheme, const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                     uint8_t *sig, size_t *sig_len) {
    if (is_ed25519(scheme)) return ed25519_sign(sk, msg, msg_len, sig, sig_len);
    return mldsa_sign(scheme, sk, msg, msg_len, sig, sig_len);
}
static int verify_with(const char *scheme, const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                       const uint8_t *sig, size_t sig_len) {
    if (is_ed25519(scheme)) return ed25519_verify(pk, msg, msg_len, sig, sig_len);
    return mldsa_verify(scheme, pk, msg, msg_len, sig, sig_len);
}
static size_t expected_sig_len(const char *scheme) {
    if (is_ed25519(scheme)) return 64;
    const SchemeSize *s = mldsa_size(scheme);
    return s ? s->sig : 0;
}
static size_t expected_pk_len(const char *scheme) {
    if (is_ed25519(scheme)) return 32;
    const SchemeSize *s = mldsa_size(scheme);
    return s ? s->pk : 0;
}
static size_t expected_sk_len(const char *scheme) {
    if (is_ed25519(scheme)) return 32;
    const SchemeSize *s = mldsa_size(scheme);
    return s ? s->sk : 0;
}

/* ---------- subcommand: genkey ---------- */

static int cmd_genkey(int argc, char **argv) {
    /* genkey <scheme> <key_id> <keydir> */
    if (argc != 5) { fprintf(stderr, "usage: release genkey <scheme> <key_id> <keydir>\n"); return 2; }
    const char *scheme = argv[2], *key_id = argv[3], *keydir = argv[4];
    if (!is_ed25519(scheme) && !mldsa_size(scheme)) {
        fprintf(stderr, "genkey: unknown scheme %s\n", scheme);
        return 2;
    }
    size_t pk_len = expected_pk_len(scheme), sk_len = expected_sk_len(scheme);
    uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
    if (!pk || !sk) return 2;
    int rc;
    if (is_ed25519(scheme)) rc = ed25519_keypair(pk, sk);
    else rc = mldsa_keypair(scheme, pk, sk);
    if (rc) { fprintf(stderr, "genkey: keypair generation failed for %s\n", scheme); return 2; }
    char pk_path[512], sk_path[512];
    snprintf(pk_path, sizeof(pk_path), "%s/%s.pk", keydir, key_id);
    snprintf(sk_path, sizeof(sk_path), "%s/%s.sk", keydir, key_id);
    if (write_file(pk_path, pk, pk_len) || write_file(sk_path, sk, sk_len)) {
        fprintf(stderr, "genkey: cannot write key files in %s\n", keydir);
        return 2;
    }
    char fp[65];
    sha256_hex(pk, pk_len, fp);
    printf("genkey: scheme=%s key_id=%s pk_len=%zu sk_len=%zu pk_sha256=%.16s...\n",
           scheme, key_id, pk_len, sk_len, fp);
    printf("genkey: wrote %s (%zu bytes) and %s (%zu bytes) — runtime keys, not for commit\n",
           pk_path, pk_len, sk_path, sk_len);
    return 0;
}

/* ---------- TBS construction ---------- */

static size_t build_tbs(char *buf, size_t cap, const char *sha_hex, uint64_t version,
                        uint64_t size, const char *c_key_id, const char *pq_key_id,
                        const char *c_scheme, const char *pq_scheme) {
    return (size_t)snprintf(buf, cap,
        "hybrid-release-manifest/1\n%s\n%llu\n%llu\n%s\n%s\n%s\n%s\n",
        sha_hex, (unsigned long long)version, (unsigned long long)size,
        c_key_id, pq_key_id, c_scheme, pq_scheme);
}

/* ---------- subcommand: sign ---------- */

static int cmd_sign(int argc, char **argv) {
    /* sign <artifact> <version> <classical_key_id> <keydir> <pq_scheme> <pq_key_id> <keydir> <manifest_out> */
    if (argc != 10) {
        fprintf(stderr, "usage: release sign <artifact> <version> <classical_key_id> <keydir> <pq_scheme> <pq_key_id> <keydir> <manifest_out>\n");
        return 2;
    }
    const char *artifact = argv[2];
    uint64_t version = strtoull(argv[3], NULL, 10);
    const char *c_key_id = argv[4], *c_keydir = argv[5];
    const char *pq_scheme = argv[6], *pq_key_id = argv[7], *pq_keydir = argv[8];
    const char *manifest_out = argv[9];
    const char *c_scheme = "Ed25519";
    if (!mldsa_size(pq_scheme)) { fprintf(stderr, "sign: unknown pq scheme %s\n", pq_scheme); return 2; }

    uint8_t *art = NULL; size_t art_len = 0;
    if (read_file(artifact, &art, &art_len)) { fprintf(stderr, "sign: cannot read artifact %s\n", artifact); return 2; }
    char sha_hex[65];
    sha256_hex(art, art_len, sha_hex);
    free(art);

    /* Load keys. */
    char path[512];
    uint8_t *c_pk = NULL, *c_sk = NULL, *pq_pk = NULL, *pq_sk = NULL;
    size_t c_pk_len, c_sk_len, pq_pk_len, pq_sk_len;
    snprintf(path, sizeof(path), "%s/%s.pk", c_keydir, c_key_id);
    if (read_file(path, &c_pk, &c_pk_len) || c_pk_len != 32) { fprintf(stderr, "sign: bad classical pk %s\n", path); return 2; }
    snprintf(path, sizeof(path), "%s/%s.sk", c_keydir, c_key_id);
    if (read_file(path, &c_sk, &c_sk_len) || c_sk_len != 32) { fprintf(stderr, "sign: bad classical sk %s\n", path); return 2; }
    snprintf(path, sizeof(path), "%s/%s.pk", pq_keydir, pq_key_id);
    if (read_file(path, &pq_pk, &pq_pk_len) || pq_pk_len != expected_pk_len(pq_scheme)) { fprintf(stderr, "sign: bad pq pk %s\n", path); return 2; }
    snprintf(path, sizeof(path), "%s/%s.sk", pq_keydir, pq_key_id);
    if (read_file(path, &pq_sk, &pq_sk_len) || pq_sk_len != expected_sk_len(pq_scheme)) { fprintf(stderr, "sign: bad pq sk %s\n", path); return 2; }

    char tbs[1024];
    size_t tbs_len = build_tbs(tbs, sizeof(tbs), sha_hex, version, art_len,
                               c_key_id, pq_key_id, c_scheme, pq_scheme);
    uint8_t c_sig[64]; size_t c_sig_len = sizeof(c_sig);
    uint8_t *pq_sig = malloc(expected_sig_len(pq_scheme));
    size_t pq_sig_len = expected_sig_len(pq_scheme);
    if (!pq_sig) return 2;
    if (sign_with(c_scheme, c_sk, (uint8_t *)tbs, tbs_len, c_sig, &c_sig_len)) {
        fprintf(stderr, "sign: classical signing failed\n"); return 2;
    }
    if (sign_with(pq_scheme, pq_sk, (uint8_t *)tbs, tbs_len, pq_sig, &pq_sig_len)) {
        fprintf(stderr, "sign: pq signing failed\n"); return 2;
    }
    char *c_pk_b64 = b64_encode(c_pk, c_pk_len);
    char *c_sig_b64 = b64_encode(c_sig, c_sig_len);
    char *pq_pk_b64 = b64_encode(pq_pk, pq_pk_len);
    char *pq_sig_b64 = b64_encode(pq_sig, pq_sig_len);
    if (!c_pk_b64 || !c_sig_b64 || !pq_pk_b64 || !pq_sig_b64) return 2;

    const char *base = strrchr(artifact, '/');
    base = base ? base + 1 : artifact;
    FILE *f = fopen(manifest_out, "w");
    if (!f) { fprintf(stderr, "sign: cannot write manifest %s\n", manifest_out); return 2; }
    fprintf(f, "{\n");
    fprintf(f, "  \"format\": \"hybrid-release-manifest/1\",\n");
    fprintf(f, "  \"artifact\": \"%s\",\n", base);
    fprintf(f, "  \"artifact_sha256\": \"%s\",\n", sha_hex);
    fprintf(f, "  \"artifact_size\": %llu,\n", (unsigned long long)art_len);
    fprintf(f, "  \"version\": %llu,\n", (unsigned long long)version);
    fprintf(f, "  \"classical_scheme\": \"%s\",\n", c_scheme);
    fprintf(f, "  \"classical_key_id\": \"%s\",\n", c_key_id);
    fprintf(f, "  \"classical_public_key_b64\": \"%s\",\n", c_pk_b64);
    fprintf(f, "  \"classical_signature_b64\": \"%s\",\n", c_sig_b64);
    fprintf(f, "  \"pq_scheme\": \"%s\",\n", pq_scheme);
    fprintf(f, "  \"pq_key_id\": \"%s\",\n", pq_key_id);
    fprintf(f, "  \"pq_public_key_b64\": \"%s\",\n", pq_pk_b64);
    fprintf(f, "  \"pq_signature_b64\": \"%s\"\n", pq_sig_b64);
    fprintf(f, "}\n");
    fclose(f);
    printf("sign: artifact=%s sha256=%s size=%zu version=%llu\n", base, sha_hex, art_len,
           (unsigned long long)version);
    printf("sign: classical %s key_id=%s sig_len=%zu\n", c_scheme, c_key_id, c_sig_len);
    printf("sign: pq %s key_id=%s sig_len=%zu\n", pq_scheme, pq_key_id, pq_sig_len);
    printf("sign: wrote manifest %s\n", manifest_out);
    return 0;
}

/* ---------- subcommand: verify ---------- */

static int read_installed_version(const char *state_file, uint64_t *out) {
    uint8_t *buf = NULL; size_t len = 0;
    if (read_file(state_file, &buf, &len)) { *out = 0; return 0; } /* no state yet: nothing installed */
    uint64_t v = 0;
    if (sscanf((char *)buf, "version=%llu", (unsigned long long *)&v) != 1) { free(buf); return -1; }
    free(buf);
    *out = v;
    return 0;
}

static int write_installed_version(const char *state_file, uint64_t v) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "version=%llu\n", (unsigned long long)v);
    return write_file(state_file, (uint8_t *)buf, (size_t)n);
}

static int key_is_revoked(const char *revocation_file, const char *key_id) {
    uint8_t *buf = NULL; size_t len = 0;
    if (read_file(revocation_file, &buf, &len)) return 0; /* no revocation file: nothing revoked */
    char *save = NULL;
    int found = 0;
    for (char *line = strtok_r((char *)buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        while (*line == ' ' || *line == '\t') line++;
        if (*line == '#' || *line == 0) continue;
        char *end = line + strlen(line);
        while (end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) *--end = 0;
        if (strcmp(line, key_id) == 0) { found = 1; break; }
    }
    free(buf);
    return found;
}

static int reject(const char *reason) {
    printf("VERDICT: REJECT\n");
    printf("REASON: %s\n", reason);
    return 1;
}

static int cmd_verify(int argc, char **argv) {
    /* verify <manifest> <artifact> <state_file> <revocation_file> */
    if (argc != 6) {
        fprintf(stderr, "usage: release verify <manifest> <artifact> <state_file> <revocation_file>\n");
        return 2;
    }
    const char *manifest = argv[2], *artifact = argv[3];
    const char *state_file = argv[4], *revocation_file = argv[5];

    uint8_t *mj = NULL; size_t mj_len = 0;
    if (read_file(manifest, &mj, &mj_len)) { fprintf(stderr, "verify: cannot read manifest %s\n", manifest); return 2; }
    char artifact_name[256] = "", sha_hex[65] = "", c_scheme[64] = "", c_key_id[128] = "";
    char c_pk_b64[8192] = "", c_sig_b64[8192] = "", pq_scheme[64] = "", pq_key_id[128] = "";
    char pq_pk_b64[8192] = "", pq_sig_b64[8192] = "";
    uint64_t version = 0, art_size = 0;
    int bad = 0;
    bad |= json_get_string((char *)mj, "artifact", artifact_name, sizeof(artifact_name));
    bad |= json_get_string((char *)mj, "artifact_sha256", sha_hex, sizeof(sha_hex));
    bad |= json_get_u64((char *)mj, "artifact_size", &art_size);
    bad |= json_get_u64((char *)mj, "version", &version);
    bad |= json_get_string((char *)mj, "classical_scheme", c_scheme, sizeof(c_scheme));
    bad |= json_get_string((char *)mj, "classical_key_id", c_key_id, sizeof(c_key_id));
    bad |= json_get_string((char *)mj, "classical_public_key_b64", c_pk_b64, sizeof(c_pk_b64));
    bad |= json_get_string((char *)mj, "classical_signature_b64", c_sig_b64, sizeof(c_sig_b64));
    bad |= json_get_string((char *)mj, "pq_scheme", pq_scheme, sizeof(pq_scheme));
    bad |= json_get_string((char *)mj, "pq_key_id", pq_key_id, sizeof(pq_key_id));
    bad |= json_get_string((char *)mj, "pq_public_key_b64", pq_pk_b64, sizeof(pq_pk_b64));
    bad |= json_get_string((char *)mj, "pq_signature_b64", pq_sig_b64, sizeof(pq_sig_b64));
    if (bad) { free(mj); return reject("manifest parse failed: missing field"); }
    printf("verify: manifest=%s artifact=%s version=%llu classical=%s key=%s pq=%s key=%s\n",
           manifest, artifact_name, (unsigned long long)version, c_scheme, c_key_id, pq_scheme, pq_key_id);

    /* 1. Artifact digest must match the manifest. */
    uint8_t *art = NULL; size_t art_len = 0;
    if (read_file(artifact, &art, &art_len)) { free(mj); fprintf(stderr, "verify: cannot read artifact %s\n", artifact); return 2; }
    char actual_sha[65];
    sha256_hex(art, art_len, actual_sha);
    free(art);
    printf("verify: artifact sha256=%s (manifest %s) size=%zu (manifest %llu)\n",
           actual_sha, sha_hex, art_len, (unsigned long long)art_size);
    if (strcmp(actual_sha, sha_hex) != 0 || art_len != art_size)
        return reject("artifact digest or size mismatch (tampered payload)");
    printf("verify: artifact digest: OK\n");

    /* 2. Monotonic version: manifest version must exceed installed version. */
    uint64_t installed = 0;
    if (read_installed_version(state_file, &installed)) { free(mj); fprintf(stderr, "verify: bad state file %s\n", state_file); return 2; }
    printf("verify: installed version=%llu manifest version=%llu\n",
           (unsigned long long)installed, (unsigned long long)version);
    if (version <= installed) {
        char reason[256];
        snprintf(reason, sizeof(reason),
                 "rollback: manifest version %llu <= installed version %llu",
                 (unsigned long long)version, (unsigned long long)installed);
        return reject(reason);
    }
    printf("verify: monotonic version: OK\n");

    /* 3. Revocation: neither key id may be revoked. */
    if (key_is_revoked(revocation_file, c_key_id)) {
        char reason[256];
        snprintf(reason, sizeof(reason), "compromised key: classical key %s is revoked", c_key_id);
        return reject(reason);
    }
    if (key_is_revoked(revocation_file, pq_key_id)) {
        char reason[256];
        snprintf(reason, sizeof(reason), "compromised key: pq key %s is revoked", pq_key_id);
        return reject(reason);
    }
    printf("verify: revocation check: OK (neither key revoked)\n");

    /* 4. FIPS 204 §3.6.2 length checks on decoded keys and signatures. */
    uint8_t *c_pk = NULL, *c_sig = NULL, *pq_pk = NULL, *pq_sig = NULL;
    size_t c_pk_len, c_sig_len, pq_pk_len, pq_sig_len;
    if (b64_decode(c_pk_b64, &c_pk, &c_pk_len) || b64_decode(c_sig_b64, &c_sig, &c_sig_len) ||
        b64_decode(pq_pk_b64, &pq_pk, &pq_pk_len) || b64_decode(pq_sig_b64, &pq_sig, &pq_sig_len)) {
        free(mj); return reject("base64 decode failed");
    }
    printf("verify: lengths classical pk=%zu (exp %zu) sig=%zu (exp %zu); pq pk=%zu (exp %zu) sig=%zu (exp %zu)\n",
           c_pk_len, expected_pk_len(c_scheme), c_sig_len, expected_sig_len(c_scheme),
           pq_pk_len, expected_pk_len(pq_scheme), pq_sig_len, expected_sig_len(pq_scheme));
    if (c_pk_len != expected_pk_len(c_scheme) || c_sig_len != expected_sig_len(c_scheme) ||
        pq_pk_len != expected_pk_len(pq_scheme) || pq_sig_len != expected_sig_len(pq_scheme) ||
        expected_pk_len(c_scheme) == 0 || expected_pk_len(pq_scheme) == 0) {
        free(mj);
        return reject("length check failed (FIPS 204 §3.6.2): key or signature length does not match scheme");
    }
    printf("verify: length checks: OK\n");

    /* 5. Independent verification of each signature over the recomputed TBS. */
    char tbs[1024];
    size_t tbs_len = build_tbs(tbs, sizeof(tbs), sha_hex, version, art_size,
                               c_key_id, pq_key_id, c_scheme, pq_scheme);
    int c_ok = verify_with(c_scheme, c_pk, (uint8_t *)tbs, tbs_len, c_sig, c_sig_len) == 0;
    int pq_ok = verify_with(pq_scheme, pq_pk, (uint8_t *)tbs, tbs_len, pq_sig, pq_sig_len) == 0;
    printf("verify: classical %s signature: %s\n", c_scheme, c_ok ? "VALID" : "INVALID");
    printf("verify: pq %s signature: %s\n", pq_scheme, pq_ok ? "VALID" : "INVALID");
    free(mj);
    if (!c_ok) return reject("classical signature verification failed");
    if (!pq_ok) return reject("pq signature verification failed");

    /* ACCEPT: record the new installed version. */
    if (write_installed_version(state_file, version)) {
        fprintf(stderr, "verify: cannot update state file %s\n", state_file);
        return 2;
    }
    printf("verify: installed version updated to %llu\n", (unsigned long long)version);
    printf("VERDICT: ACCEPT\n");
    printf("REASON: artifact digest, monotonic version, revocation, lengths, and both signatures valid\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: release <genkey|sign|verify> ...\n");
        return 2;
    }
    printf("release: liboqs %s, OpenSSL %s\n", OQS_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
    if (strcmp(argv[1], "genkey") == 0) return cmd_genkey(argc, argv);
    if (strcmp(argv[1], "sign") == 0) return cmd_sign(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);
    fprintf(stderr, "release: unknown subcommand %s\n", argv[1]);
    return 2;
}

/* recovery.c — SLH-DSA recovery signing and verification for releases.
 *
 * This is the recovery extension to the hybrid release-signing harness
 * (src/release.c): when the primary hybrid signature (Ed25519 + ML-DSA)
 * can no longer be used — the ML-DSA key was compromised and revoked, or
 * the primary signature itself is corrupt — a release can still be
 * installed if it carries a valid SLH-DSA fallback signature. The
 * fallback key is itself revocable, and the same monotonic version
 * counter and revocation list as the primary harness apply.
 *
 * Subcommands:
 *   genkey <scheme> <key_id> <keydir>
 *       scheme: one of the twelve FIPS 205 pure SLH-DSA sets, written in
 *       the FIPS 205 name form, e.g. SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128f.
 *       Writes raw key files <keydir>/<key_id>.pk and .sk (runtime-generated
 *       keys only; never commit them). Prints lengths and the full SHA-256
 *       fingerprint of the public key for logging.
 *   sign <artifact> <version> <fallback_scheme> <fallback_key_id> <keydir>
 *        <manifest_out>
 *       Computes SHA-256 of the artifact, builds the canonical to-be-signed
 *       (TBS) string, signs it with SLH-DSA (pure, FIPS 205), and writes a
 *       flat JSON recovery release manifest (format recovery-release-manifest/1).
 *   verify <manifest> <artifact> <state_file> <revocation_file>
 *       Recomputes the artifact digest, enforces the monotonic version
 *       (manifest version must exceed the installed version in state_file),
 *       rejects a revoked fallback key id, applies FIPS 205 length checks
 *       (key/signature lengths from the pinned liboqs implementation for
 *       the named scheme), then verifies the SLH-DSA signature against the
 *       recomputed TBS. On ACCEPT the state file is updated to the manifest
 *       version. Exit 0 = ACCEPT, 1 = REJECT, 2 = usage/internal error.
 *       Prints "VERDICT: ACCEPT|REJECT" and "REASON: ..." for drivers.
 *
 * The TBS string is:
 *   recovery-release-manifest/1\n<sha256hex>\n<version>\n<size>\n
 *   <fallback_key_id>\n<fallback_scheme>\n
 *
 * The recovery manifest stands alone: it covers the artifact digest, the
 * version, and the fallback key, but it does NOT carry or bind the primary
 * hybrid signatures. The linkage between a recovery manifest and the
 * hybrid release it recovers is operational (same artifact bytes, same
 * version number) and is demonstrated by the scenario suite, not by a
 * cryptographic binding. See docs/methodology.md (design decision D4).
 *
 * Expected sizes are checked against the pinned liboqs 0.16.0
 * implementation, whose SLH-DSA lengths are asserted against FIPS 205
 * Table 2 by src/bench_slhdsa.c. SLH-DSA is stateless: no per-signature
 * state is kept, and a fallback key can sign any number of releases
 * (up to 2^64 per FIPS 205).
 *
 * Compile: cc -O2 -I<liboqs include> recovery.c -L<liboqs lib> -loqs -lcrypto -o recovery
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

/* ---------- small utilities (same shape as src/release.c) ---------- */

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

/* Flat-JSON helpers: the manifest is flat, keys unique, values strings or
 * numbers. Values are allocated dynamically: an SLH-DSA-256f signature is
 * 49,856 bytes, ~66,475 base64 characters, so fixed buffers do not fit. */
static int json_get_string(const char *json, const char *key, char **out) {
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
    char *buf = malloc(n + 1);
    if (!buf) return -1;
    memcpy(buf, p, n);
    buf[n] = 0;
    *out = buf;
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

/* ---------- scheme table: FIPS 205 names -> liboqs algorithm names ----------
 * The manifest carries the FIPS 205 name (e.g. SLH-DSA-SHA2-128s); liboqs
 * 0.16.0 names the same algorithm SLH_DSA_PURE_SHA2_128S. The mapping is
 * exact and exhaustive for the twelve pure parameter sets. */

typedef struct { const char *fips_name; const char *oqs_name; } SchemeMap;
static const SchemeMap SCHEMES[] = {
    { "SLH-DSA-SHA2-128s", "SLH_DSA_PURE_SHA2_128S" },
    { "SLH-DSA-SHA2-128f", "SLH_DSA_PURE_SHA2_128F" },
    { "SLH-DSA-SHA2-192s", "SLH_DSA_PURE_SHA2_192S" },
    { "SLH-DSA-SHA2-192f", "SLH_DSA_PURE_SHA2_192F" },
    { "SLH-DSA-SHA2-256s", "SLH_DSA_PURE_SHA2_256S" },
    { "SLH-DSA-SHA2-256f", "SLH_DSA_PURE_SHA2_256F" },
    { "SLH-DSA-SHAKE-128s", "SLH_DSA_PURE_SHAKE_128S" },
    { "SLH-DSA-SHAKE-128f", "SLH_DSA_PURE_SHAKE_128F" },
    { "SLH-DSA-SHAKE-192s", "SLH_DSA_PURE_SHAKE_192S" },
    { "SLH-DSA-SHAKE-192f", "SLH_DSA_PURE_SHAKE_192F" },
    { "SLH-DSA-SHAKE-256s", "SLH_DSA_PURE_SHAKE_256S" },
    { "SLH-DSA-SHAKE-256f", "SLH_DSA_PURE_SHAKE_256F" },
};
static const char *oqs_name_for(const char *fips_name) {
    for (size_t i = 0; i < sizeof(SCHEMES) / sizeof(SCHEMES[0]); i++)
        if (strcmp(fips_name, SCHEMES[i].fips_name) == 0) return SCHEMES[i].oqs_name;
    return NULL;
}

/* ---------- SLH-DSA via liboqs ---------- */

static int slhdsa_keypair(const char *fips_name, uint8_t *pk, uint8_t *sk) {
    const char *alg = oqs_name_for(fips_name);
    if (!alg) return -1;
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    int rc = OQS_SIG_keypair(s, pk, sk) == OQS_SUCCESS ? 0 : -1;
    OQS_SIG_free(s);
    return rc;
}

static int slhdsa_sign(const char *fips_name, const uint8_t *sk, const uint8_t *msg, size_t msg_len,
                       uint8_t *sig, size_t *sig_len) {
    const char *alg = oqs_name_for(fips_name);
    if (!alg) return -1;
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    int rc = OQS_SIG_sign(s, sig, sig_len, msg, msg_len, sk) == OQS_SUCCESS ? 0 : -1;
    OQS_SIG_free(s);
    return rc;
}

static int slhdsa_verify(const char *fips_name, const uint8_t *pk, const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len) {
    const char *alg = oqs_name_for(fips_name);
    if (!alg) return -1;
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    int rc = OQS_SIG_verify(s, msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS ? 0 : -1;
    OQS_SIG_free(s);
    return rc;
}

/* Expected lengths for a scheme, from the pinned liboqs implementation. */
static int slhdsa_lengths(const char *fips_name, size_t *sk, size_t *pk, size_t *sig) {
    const char *alg = oqs_name_for(fips_name);
    if (!alg) return -1;
    OQS_SIG *s = OQS_SIG_new(alg);
    if (!s) return -1;
    *sk = s->length_secret_key;
    *pk = s->length_public_key;
    *sig = s->length_signature;
    OQS_SIG_free(s);
    return 0;
}

/* ---------- subcommand: genkey ---------- */

static int cmd_genkey(int argc, char **argv) {
    /* genkey <scheme> <key_id> <keydir> */
    if (argc != 5) { fprintf(stderr, "usage: recovery genkey <scheme> <key_id> <keydir>\n"); return 2; }
    const char *scheme = argv[2], *key_id = argv[3], *keydir = argv[4];
    size_t sk_len = 0, pk_len = 0, sig_len = 0;
    if (slhdsa_lengths(scheme, &sk_len, &pk_len, &sig_len)) {
        fprintf(stderr, "genkey: unknown scheme %s (expected a FIPS 205 pure SLH-DSA name)\n", scheme);
        return 2;
    }
    uint8_t *pk = malloc(pk_len), *sk = malloc(sk_len);
    if (!pk || !sk) return 2;
    if (slhdsa_keypair(scheme, pk, sk)) {
        fprintf(stderr, "genkey: keypair generation failed for %s\n", scheme);
        return 2;
    }
    char pk_path[512], sk_path[512];
    snprintf(pk_path, sizeof(pk_path), "%s/%s.pk", keydir, key_id);
    snprintf(sk_path, sizeof(sk_path), "%s/%s.sk", keydir, key_id);
    if (write_file(pk_path, pk, pk_len) || write_file(sk_path, sk, sk_len)) {
        fprintf(stderr, "genkey: cannot write key files in %s\n", keydir);
        return 2;
    }
    char fp[65];
    sha256_hex(pk, pk_len, fp);
    printf("genkey: scheme=%s key_id=%s pk_len=%zu sk_len=%zu sig_len=%zu pk_sha256=%s\n",
           scheme, key_id, pk_len, sk_len, sig_len, fp);
    printf("genkey: wrote %s (%zu bytes) and %s (%zu bytes) — runtime keys, not for commit\n",
           pk_path, pk_len, sk_path, sk_len);
    return 0;
}

/* ---------- TBS construction ---------- */

static size_t build_tbs(char *buf, size_t cap, const char *sha_hex, uint64_t version,
                        uint64_t size, const char *fb_key_id, const char *fb_scheme) {
    return (size_t)snprintf(buf, cap,
        "recovery-release-manifest/1\n%s\n%llu\n%llu\n%s\n%s\n",
        sha_hex, (unsigned long long)version, (unsigned long long)size,
        fb_key_id, fb_scheme);
}

/* ---------- subcommand: sign ---------- */

static int cmd_sign(int argc, char **argv) {
    /* sign <artifact> <version> <fallback_scheme> <fallback_key_id> <keydir> <manifest_out> */
    if (argc != 8) {
        fprintf(stderr, "usage: recovery sign <artifact> <version> <fallback_scheme> <fallback_key_id> <keydir> <manifest_out>\n");
        return 2;
    }
    const char *artifact = argv[2];
    uint64_t version = strtoull(argv[3], NULL, 10);
    const char *fb_scheme = argv[4], *fb_key_id = argv[5], *keydir = argv[6];
    const char *manifest_out = argv[7];
    size_t sk_len = 0, pk_len = 0, sig_len = 0;
    if (slhdsa_lengths(fb_scheme, &sk_len, &pk_len, &sig_len)) {
        fprintf(stderr, "sign: unknown fallback scheme %s\n", fb_scheme);
        return 2;
    }

    uint8_t *art = NULL; size_t art_len = 0;
    if (read_file(artifact, &art, &art_len)) { fprintf(stderr, "sign: cannot read artifact %s\n", artifact); return 2; }
    char sha_hex[65];
    sha256_hex(art, art_len, sha_hex);
    free(art);

    char path[512];
    uint8_t *fb_pk = NULL, *fb_sk = NULL;
    size_t fb_pk_len, fb_sk_len;
    snprintf(path, sizeof(path), "%s/%s.pk", keydir, fb_key_id);
    if (read_file(path, &fb_pk, &fb_pk_len) || fb_pk_len != pk_len) { fprintf(stderr, "sign: bad fallback pk %s\n", path); return 2; }
    snprintf(path, sizeof(path), "%s/%s.sk", keydir, fb_key_id);
    if (read_file(path, &fb_sk, &fb_sk_len) || fb_sk_len != sk_len) { fprintf(stderr, "sign: bad fallback sk %s\n", path); return 2; }

    char tbs[1024];
    size_t tbs_len = build_tbs(tbs, sizeof(tbs), sha_hex, version, art_len, fb_key_id, fb_scheme);
    uint8_t *fb_sig = malloc(sig_len);
    size_t fb_sig_len = sig_len;
    if (!fb_sig) return 2;
    if (slhdsa_sign(fb_scheme, fb_sk, (uint8_t *)tbs, tbs_len, fb_sig, &fb_sig_len)) {
        fprintf(stderr, "sign: fallback signing failed\n"); return 2;
    }
    if (fb_sig_len != sig_len) {
        fprintf(stderr, "sign: produced signature length %zu != expected %zu\n", fb_sig_len, sig_len);
        return 2;
    }
    char *fb_pk_b64 = b64_encode(fb_pk, fb_pk_len);
    char *fb_sig_b64 = b64_encode(fb_sig, fb_sig_len);
    if (!fb_pk_b64 || !fb_sig_b64) return 2;

    const char *base = strrchr(artifact, '/');
    base = base ? base + 1 : artifact;
    FILE *f = fopen(manifest_out, "w");
    if (!f) { fprintf(stderr, "sign: cannot write manifest %s\n", manifest_out); return 2; }
    fprintf(f, "{\n");
    fprintf(f, "  \"format\": \"recovery-release-manifest/1\",\n");
    fprintf(f, "  \"artifact\": \"%s\",\n", base);
    fprintf(f, "  \"artifact_sha256\": \"%s\",\n", sha_hex);
    fprintf(f, "  \"artifact_size\": %llu,\n", (unsigned long long)art_len);
    fprintf(f, "  \"version\": %llu,\n", (unsigned long long)version);
    fprintf(f, "  \"fallback_scheme\": \"%s\",\n", fb_scheme);
    fprintf(f, "  \"fallback_key_id\": \"%s\",\n", fb_key_id);
    fprintf(f, "  \"fallback_public_key_b64\": \"%s\",\n", fb_pk_b64);
    fprintf(f, "  \"fallback_signature_b64\": \"%s\"\n", fb_sig_b64);
    fprintf(f, "}\n");
    fclose(f);
    printf("sign: artifact=%s sha256=%s size=%zu version=%llu\n", base, sha_hex, art_len,
           (unsigned long long)version);
    printf("sign: fallback %s key_id=%s sig_len=%zu\n", fb_scheme, fb_key_id, fb_sig_len);
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
        fprintf(stderr, "usage: recovery verify <manifest> <artifact> <state_file> <revocation_file>\n");
        return 2;
    }
    const char *manifest = argv[2], *artifact = argv[3];
    const char *state_file = argv[4], *revocation_file = argv[5];

    uint8_t *mj = NULL; size_t mj_len = 0;
    if (read_file(manifest, &mj, &mj_len)) { fprintf(stderr, "verify: cannot read manifest %s\n", manifest); return 2; }
    char *artifact_name = NULL, *sha_hex = NULL, *fb_scheme = NULL, *fb_key_id = NULL;
    char *fb_pk_b64 = NULL, *fb_sig_b64 = NULL;
    uint64_t version = 0, art_size = 0;
    int bad = 0;
    bad |= json_get_string((char *)mj, "artifact", &artifact_name);
    bad |= json_get_string((char *)mj, "artifact_sha256", &sha_hex);
    bad |= json_get_u64((char *)mj, "artifact_size", &art_size);
    bad |= json_get_u64((char *)mj, "version", &version);
    bad |= json_get_string((char *)mj, "fallback_scheme", &fb_scheme);
    bad |= json_get_string((char *)mj, "fallback_key_id", &fb_key_id);
    bad |= json_get_string((char *)mj, "fallback_public_key_b64", &fb_pk_b64);
    bad |= json_get_string((char *)mj, "fallback_signature_b64", &fb_sig_b64);
    if (bad) { free(mj); return reject("manifest parse failed: missing field"); }
    printf("verify: manifest=%s artifact=%s version=%llu fallback=%s key=%s\n",
           manifest, artifact_name, (unsigned long long)version, fb_scheme, fb_key_id);

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

    /* 3. Revocation: the fallback key id must not be revoked. */
    if (key_is_revoked(revocation_file, fb_key_id)) {
        char reason[256];
        snprintf(reason, sizeof(reason), "compromised key: fallback key %s is revoked", fb_key_id);
        return reject(reason);
    }
    printf("verify: revocation check: OK (fallback key not revoked)\n");

    /* 4. FIPS 205 length checks on the decoded key and signature, against
     * the pinned liboqs lengths for the named scheme. */
    size_t exp_sk = 0, exp_pk = 0, exp_sig = 0;
    if (slhdsa_lengths(fb_scheme, &exp_sk, &exp_pk, &exp_sig)) {
        free(mj);
        return reject("unknown fallback scheme (not a FIPS 205 pure SLH-DSA set)");
    }
    uint8_t *fb_pk = NULL, *fb_sig = NULL;
    size_t fb_pk_len, fb_sig_len;
    if (b64_decode(fb_pk_b64, &fb_pk, &fb_pk_len) || b64_decode(fb_sig_b64, &fb_sig, &fb_sig_len)) {
        free(mj); return reject("base64 decode failed");
    }
    printf("verify: lengths fallback pk=%zu (exp %zu) sig=%zu (exp %zu)\n",
           fb_pk_len, exp_pk, fb_sig_len, exp_sig);
    if (fb_pk_len != exp_pk || fb_sig_len != exp_sig) {
        free(mj);
        return reject("length check failed (FIPS 205): fallback key or signature length does not match scheme");
    }
    printf("verify: length checks: OK\n");

    /* 5. SLH-DSA signature verification over the recomputed TBS. */
    char tbs[1024];
    size_t tbs_len = build_tbs(tbs, sizeof(tbs), sha_hex, version, art_size, fb_key_id, fb_scheme);
    int fb_ok = slhdsa_verify(fb_scheme, fb_pk, (uint8_t *)tbs, tbs_len, fb_sig, fb_sig_len) == 0;
    printf("verify: fallback %s signature: %s\n", fb_scheme, fb_ok ? "VALID" : "INVALID");
    free(mj);
    if (!fb_ok) return reject("fallback signature verification failed");

    /* ACCEPT: record the new installed version. */
    if (write_installed_version(state_file, version)) {
        fprintf(stderr, "verify: cannot update state file %s\n", state_file);
        return 2;
    }
    printf("verify: installed version updated to %llu\n", (unsigned long long)version);
    printf("VERDICT: ACCEPT\n");
    printf("REASON: artifact digest, monotonic version, revocation, lengths, and fallback signature valid\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: recovery <genkey|sign|verify> ...\n");
        return 2;
    }
    printf("recovery: liboqs %s, OpenSSL %s\n", OQS_VERSION_TEXT, OpenSSL_version(OPENSSL_VERSION));
    if (strcmp(argv[1], "genkey") == 0) return cmd_genkey(argc, argv);
    if (strcmp(argv[1], "sign") == 0) return cmd_sign(argc, argv);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc, argv);
    fprintf(stderr, "recovery: unknown subcommand %s\n", argv[1]);
    return 2;
}

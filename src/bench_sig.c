/* bench_sig.c — ML-DSA-44/65/87 + Ed25519 size and timing bench.
 *
 * Asserts the FIPS 204 Table 2 sizes for ML-DSA (sk/pk/sig) and the
 * RFC 8032 sizes for Ed25519 (pk 32, sig 64), then times keypair / sign /
 * verify over N iterations on a fixed 64-byte message and verifies the
 * produced signature on every iteration. ML-DSA via the liboqs C API
 * (OQS_SIG); Ed25519 via OpenSSL 3 EVP (pure Ed25519, NULL digest).
 *
 * Usage: bench_sig [iterations]   (default 100)
 * Compile: cc -O2 -I<liboqs include> bench_sig.c -L<liboqs lib> -loqs -lcrypto -o bench_sig
 *
 * CSV lines ("CSV: scheme,op,n,mean_us,min_us,max_us,rate_ops_s") are
 * machine-readable; everything else is human-readable log output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/err.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

typedef struct { double total_s, min_us, max_us; int n; } Stats;
static void s_init(Stats *s) { s->total_s = 0; s->min_us = 1e18; s->max_us = 0; s->n = 0; }
static void s_add(Stats *s, double dt) {
    double us = dt * 1e6;
    s->total_s += dt;
    if (us < s->min_us) s->min_us = us;
    if (us > s->max_us) s->max_us = us;
    s->n++;
}
static void s_print(const char *label, const Stats *s) {
    printf("%-24s n=%-5d mean=%9.2f us  min=%9.2f us  max=%9.2f us  rate=%9.2f ops/s\n",
           label, s->n, s->total_s * 1e6 / s->n, s->min_us, s->max_us, s->n / s->total_s);
    printf("CSV: %s,n=%d,mean_us=%.2f,min_us=%.2f,max_us=%.2f,rate_ops_s=%.2f\n",
           label, s->n, s->total_s * 1e6 / s->n, s->min_us, s->max_us, s->n / s->total_s);
}

static const uint8_t MSG[64] = {
    0x48,0x79,0x62,0x72,0x69,0x64,0x20,0x66,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,0x20,
    0x73,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x62,0x65,0x6e,0x63,0x68,0x6d,0x61,0x72,
    0x6b,0x20,0x6d,0x65,0x73,0x73,0x61,0x67,0x65,0x20,0x2d,0x20,0x66,0x69,0x78,0x65,
    0x64,0x20,0x36,0x34,0x20,0x62,0x79,0x74,0x65,0x73,0x20,0x66,0x6f,0x72,0x20,0x74
};

typedef struct {
    const char *name;          /* liboqs algorithm name */
    size_t exp_sk, exp_pk, exp_sig;
    int category;              /* FIPS 204 security strength category */
} MlDsaParam;

static int bench_mldsa(const MlDsaParam *p, int n) {
    OQS_SIG *sig = OQS_SIG_new(p->name);
    if (!sig) { fprintf(stderr, "FATAL: OQS_SIG_new(%s) failed\n", p->name); return 1; }
    printf("[%s] algorithm: %s (FIPS 204 category %d)\n", p->name, sig->method_name, p->category);
    int ok = 1;
    printf("[%s] length_secret_key=%zu (FIPS 204 Table 2: %zu) %s\n", p->name,
           sig->length_secret_key, p->exp_sk, sig->length_secret_key == p->exp_sk ? "OK" : "MISMATCH");
    printf("[%s] length_public_key=%zu (FIPS 204 Table 2: %zu) %s\n", p->name,
           sig->length_public_key, p->exp_pk, sig->length_public_key == p->exp_pk ? "OK" : "MISMATCH");
    printf("[%s] length_signature=%zu (FIPS 204 Table 2: %zu) %s\n", p->name,
           sig->length_signature, p->exp_sig, sig->length_signature == p->exp_sig ? "OK" : "MISMATCH");
    if (sig->length_secret_key != p->exp_sk || sig->length_public_key != p->exp_pk ||
        sig->length_signature != p->exp_sig) ok = 0;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *sg = malloc(sig->length_signature);
    if (!pk || !sk || !sg) { fprintf(stderr, "FATAL: malloc\n"); return 1; }

    Stats kg, sn, vf;
    s_init(&kg); s_init(&sn); s_init(&vf);
    int verify_fail = 0;
    char label[64];
    for (int i = 0; i < n; i++) {
        double t0 = now_s();
        if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: keypair\n"); return 1; }
        s_add(&kg, now_s() - t0);
        size_t sg_len = 0;
        t0 = now_s();
        if (OQS_SIG_sign(sig, sg, &sg_len, MSG, sizeof(MSG), sk) != OQS_SUCCESS) { fprintf(stderr, "FATAL: sign\n"); return 1; }
        s_add(&sn, now_s() - t0);
        if (sg_len != sig->length_signature) {
            printf("[%s] WARNING: produced signature length %zu != length_signature %zu\n",
                   p->name, sg_len, sig->length_signature);
        }
        t0 = now_s();
        if (OQS_SIG_verify(sig, MSG, sizeof(MSG), sg, sg_len, pk) != OQS_SUCCESS) verify_fail++;
        s_add(&vf, now_s() - t0);
    }
    snprintf(label, sizeof(label), "%s keypair", p->name); s_print(label, &kg);
    snprintf(label, sizeof(label), "%s sign", p->name);    s_print(label, &sn);
    snprintf(label, sizeof(label), "%s verify", p->name);  s_print(label, &vf);
    printf("[%s] verify failures: %d / %d\n", p->name, verify_fail, n);
    if (verify_fail) ok = 0;
    free(pk); free(sk); free(sg);
    OQS_SIG_free(sig);
    printf("[%s] sizes+roundtrip: %s\n", p->name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int bench_ed25519(int n) {
    /* RFC 8032 §1: Ed25519 public keys 32 bytes, signatures 64 bytes. */
    printf("[Ed25519] algorithm: Ed25519 (RFC 8032, OpenSSL EVP)\n");
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519", NULL);
    if (!pkey) { fprintf(stderr, "FATAL: Ed25519 keygen\n"); ERR_print_errors_fp(stderr); return 1; }
    size_t pk_len = 0, sk_len = 0;
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pk_len);
    EVP_PKEY_get_raw_private_key(pkey, NULL, &sk_len);
    printf("[Ed25519] public_key=%zu bytes (RFC 8032: 32) %s\n", pk_len, pk_len == 32 ? "OK" : "MISMATCH");
    printf("[Ed25519] private_key=%zu bytes (raw seed, RFC 8032 §3.2: 32) %s\n", sk_len, sk_len == 32 ? "OK" : "MISMATCH");
    int ok = (pk_len == 32 && sk_len == 32);

    unsigned char sig[64];
    size_t sig_len = sizeof(sig);
    Stats kg, sn, vf;
    s_init(&kg); s_init(&sn); s_init(&vf);
    int verify_fail = 0;
    for (int i = 0; i < n; i++) {
        double t0 = now_s();
        EVP_PKEY_free(pkey);
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519", NULL);
        if (!pkey) { fprintf(stderr, "FATAL: Ed25519 keygen\n"); return 1; }
        s_add(&kg, now_s() - t0);
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        sig_len = sizeof(sig);
        t0 = now_s();
        if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1 ||
            EVP_DigestSign(ctx, sig, &sig_len, MSG, sizeof(MSG)) != 1) {
            fprintf(stderr, "FATAL: Ed25519 sign\n"); ERR_print_errors_fp(stderr); return 1;
        }
        s_add(&sn, now_s() - t0);
        if (sig_len != 64) printf("[Ed25519] WARNING: produced signature length %zu != 64\n", sig_len);
        EVP_MD_CTX *vctx = EVP_MD_CTX_new();
        t0 = now_s();
        int rc = (EVP_DigestVerifyInit(vctx, NULL, NULL, NULL, pkey) == 1) &&
                 (EVP_DigestVerify(vctx, sig, sig_len, MSG, sizeof(MSG)) == 1);
        s_add(&vf, now_s() - t0);
        if (!rc) verify_fail++;
        EVP_MD_CTX_free(ctx);
        EVP_MD_CTX_free(vctx);
    }
    printf("[Ed25519] signature=%zu bytes (RFC 8032: 64) %s\n", sig_len, sig_len == 64 ? "OK" : "MISMATCH");
    if (sig_len != 64) ok = 0;
    s_print("Ed25519 keypair", &kg);
    s_print("Ed25519 sign", &sn);
    s_print("Ed25519 verify", &vf);
    printf("[Ed25519] verify failures: %d / %d\n", verify_fail, n);
    if (verify_fail) ok = 0;
    EVP_PKEY_free(pkey);
    printf("[Ed25519] sizes+roundtrip: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 100;
    printf("bench_sig: ML-DSA + Ed25519 size and timing check\n");
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("iterations: %d (fixed 64-byte message)\n", n);
    printf("expected sizes: FIPS 204 Table 2 (ML-DSA), RFC 8032 §1 (Ed25519)\n");

    static const MlDsaParam params[] = {
        { OQS_SIG_alg_ml_dsa_44, 2560, 1312, 2420, 2 },
        { OQS_SIG_alg_ml_dsa_65, 4032, 1952, 3309, 3 },
        { OQS_SIG_alg_ml_dsa_87, 4896, 2592, 4627, 5 },
    };
    int rc = 0;
    for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++)
        rc |= bench_mldsa(&params[i], n);
    rc |= bench_ed25519(n);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("peak RSS: %ld KiB\n", ru.ru_maxrss);
    printf("bench_sig: %s\n", rc ? "FAIL" : "DONE");
    return rc;
}

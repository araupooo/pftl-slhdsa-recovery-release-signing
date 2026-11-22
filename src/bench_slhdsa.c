/* bench_slhdsa.c — SLH-DSA size and timing bench (all twelve pure sets).
 *
 * Asserts the FIPS 205 Table 2 sizes for SLH-DSA (sk/pk/sig) for every
 * pure parameter set (SHA2 and SHAKE families, 128/192/256, s/f tunings),
 * then times keypair / sign / verify on a fixed 64-byte message and
 * verifies the produced signature on every iteration. SLH-DSA via the
 * liboqs C API (OQS_SIG).
 *
 * Iteration counts: 100 for the 128s/128f sets (the decision-relevant
 * fallback candidates); 5 for the 192/256 sets (signing there is slow
 * enough that 100 iterations would take several minutes — the 192/256
 * rows exist to prove the sizes and that a roundtrip works, not to
 * produce tight timing statistics). The iteration count is printed per
 * set, so no row can be mistaken for an N=100 measurement.
 *
 * Usage: bench_slhdsa [iterations-128] [iterations-rest]
 *        defaults: 100 and 5.
 * Compile: cc -O2 -I<liboqs include> bench_slhdsa.c -L<liboqs lib> -loqs -lcrypto -o bench_slhdsa
 *
 * CSV lines ("CSV: scheme,op,n,mean_us,min_us,max_us,rate_ops_s") are
 * machine-readable; the median is printed on the human-readable line.
 * Everything else is human-readable log output.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <oqs/oqs.h>

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

typedef struct { double total_s, min_us, max_us; double *samples; int n, cap; } Stats;
static void s_init(Stats *s, int cap) {
    s->total_s = 0; s->min_us = 1e18; s->max_us = 0; s->n = 0; s->cap = cap;
    s->samples = malloc(sizeof(double) * (size_t)cap);
}
static int cmp_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static void s_add(Stats *s, double dt) {
    double us = dt * 1e6;
    s->total_s += dt;
    if (us < s->min_us) s->min_us = us;
    if (us > s->max_us) s->max_us = us;
    if (s->n < s->cap) s->samples[s->n] = us;
    s->n++;
}
static double s_median(Stats *s) {
    if (s->n == 0) return 0;
    qsort(s->samples, (size_t)s->n, sizeof(double), cmp_double);
    if (s->n % 2) return s->samples[s->n / 2];
    return (s->samples[s->n / 2 - 1] + s->samples[s->n / 2]) / 2.0;
}
static void s_print(const char *label, Stats *s) {
    printf("%-28s n=%-5d mean=%12.2f us  median=%12.2f us  min=%12.2f us  max=%12.2f us  rate=%9.2f ops/s\n",
           label, s->n, s->total_s * 1e6 / s->n, s_median(s), s->min_us, s->max_us, s->n / s->total_s);
    printf("CSV: %s,n=%d,mean_us=%.2f,min_us=%.2f,max_us=%.2f,rate_ops_s=%.2f\n",
           label, s->n, s->total_s * 1e6 / s->n, s->min_us, s->max_us, s->n / s->total_s);
    free(s->samples);
}

static const uint8_t MSG[64] = {
    0x53,0x4c,0x48,0x2d,0x44,0x53,0x41,0x20,0x66,0x61,0x6c,0x6c,0x62,0x61,0x63,0x6b,
    0x20,0x62,0x65,0x6e,0x63,0x68,0x6d,0x61,0x72,0x6b,0x20,0x6d,0x65,0x73,0x73,0x61,
    0x67,0x65,0x20,0x2d,0x20,0x66,0x69,0x78,0x65,0x64,0x20,0x36,0x34,0x20,0x62,0x79,
    0x74,0x65,0x73,0x20,0x66,0x6f,0x72,0x20,0x74,0x65,0x73,0x74,0x69,0x6e,0x67,0x2e
};

typedef struct {
    const char *oqs_name;      /* liboqs algorithm name */
    const char *fips_name;     /* FIPS 205 name, for the log */
    size_t exp_sk, exp_pk, exp_sig;
    int category;              /* FIPS 205 security strength category */
} SlhParam;

static int bench_one(const SlhParam *p, int n) {
    OQS_SIG *sig = OQS_SIG_new(p->oqs_name);
    if (!sig) { fprintf(stderr, "FATAL: OQS_SIG_new(%s) failed\n", p->oqs_name); return 1; }
    printf("[%s] algorithm: %s (FIPS 205 category %d, %s)\n", p->fips_name,
           sig->method_name, p->category, p->oqs_name);
    int ok = 1;
    printf("[%s] length_secret_key=%zu (FIPS 205 Table 2: %zu) %s\n", p->fips_name,
           sig->length_secret_key, p->exp_sk, sig->length_secret_key == p->exp_sk ? "OK" : "MISMATCH");
    printf("[%s] length_public_key=%zu (FIPS 205 Table 2: %zu) %s\n", p->fips_name,
           sig->length_public_key, p->exp_pk, sig->length_public_key == p->exp_pk ? "OK" : "MISMATCH");
    printf("[%s] length_signature=%zu (FIPS 205 Table 2: %zu) %s\n", p->fips_name,
           sig->length_signature, p->exp_sig, sig->length_signature == p->exp_sig ? "OK" : "MISMATCH");
    if (sig->length_secret_key != p->exp_sk || sig->length_public_key != p->exp_pk ||
        sig->length_signature != p->exp_sig) ok = 0;

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *sg = malloc(sig->length_signature);
    if (!pk || !sk || !sg) { fprintf(stderr, "FATAL: malloc\n"); return 1; }

    Stats kg, sn, vf;
    s_init(&kg, n); s_init(&sn, n); s_init(&vf, n);
    int verify_fail = 0;
    char label[96];
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
                   p->fips_name, sg_len, sig->length_signature);
        }
        t0 = now_s();
        if (OQS_SIG_verify(sig, MSG, sizeof(MSG), sg, sg_len, pk) != OQS_SUCCESS) verify_fail++;
        s_add(&vf, now_s() - t0);
    }
    snprintf(label, sizeof(label), "%s keypair", p->fips_name); s_print(label, &kg);
    snprintf(label, sizeof(label), "%s sign", p->fips_name);    s_print(label, &sn);
    snprintf(label, sizeof(label), "%s verify", p->fips_name);  s_print(label, &vf);
    printf("[%s] verify failures: %d / %d\n", p->fips_name, verify_fail, n);
    if (verify_fail) ok = 0;
    free(pk); free(sk); free(sg);
    OQS_SIG_free(sig);
    printf("[%s] sizes+roundtrip: %s\n", p->fips_name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

int main(int argc, char **argv) {
    int n128 = argc > 1 ? atoi(argv[1]) : 100;
    int nrest = argc > 2 ? atoi(argv[2]) : 5;
    printf("bench_slhdsa: SLH-DSA size and timing check (all twelve pure sets)\n");
    printf("liboqs version: %s\n", OQS_VERSION_TEXT);
    printf("iterations: %d for 128s/128f sets, %d for 192/256 sets (fixed 64-byte message)\n", n128, nrest);
    printf("expected sizes: FIPS 205 Table 2 (sk = 4n, pk = 2n, signature per set)\n");

    static const SlhParam params[] = {
        { OQS_SIG_alg_slh_dsa_pure_sha2_128s, "SLH-DSA-SHA2-128s", 64, 32, 7856, 1 },
        { OQS_SIG_alg_slh_dsa_pure_sha2_128f, "SLH-DSA-SHA2-128f", 64, 32, 17088, 1 },
        { OQS_SIG_alg_slh_dsa_pure_sha2_192s, "SLH-DSA-SHA2-192s", 96, 48, 16224, 3 },
        { OQS_SIG_alg_slh_dsa_pure_sha2_192f, "SLH-DSA-SHA2-192f", 96, 48, 35664, 3 },
        { OQS_SIG_alg_slh_dsa_pure_sha2_256s, "SLH-DSA-SHA2-256s", 128, 64, 29792, 5 },
        { OQS_SIG_alg_slh_dsa_pure_sha2_256f, "SLH-DSA-SHA2-256f", 128, 64, 49856, 5 },
        { OQS_SIG_alg_slh_dsa_pure_shake_128s, "SLH-DSA-SHAKE-128s", 64, 32, 7856, 1 },
        { OQS_SIG_alg_slh_dsa_pure_shake_128f, "SLH-DSA-SHAKE-128f", 64, 32, 17088, 1 },
        { OQS_SIG_alg_slh_dsa_pure_shake_192s, "SLH-DSA-SHAKE-192s", 96, 48, 16224, 3 },
        { OQS_SIG_alg_slh_dsa_pure_shake_192f, "SLH-DSA-SHAKE-192f", 96, 48, 35664, 3 },
        { OQS_SIG_alg_slh_dsa_pure_shake_256s, "SLH-DSA-SHAKE-256s", 128, 64, 29792, 5 },
        { OQS_SIG_alg_slh_dsa_pure_shake_256f, "SLH-DSA-SHAKE-256f", 128, 64, 49856, 5 },
    };
    int rc = 0;
    for (size_t i = 0; i < sizeof(params) / sizeof(params[0]); i++) {
        /* 128s/128f get the full iteration count; the rest get nrest. */
        int is128 = strstr(params[i].fips_name, "-128") != NULL;
        rc |= bench_one(&params[i], is128 ? n128 : nrest);
    }
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    printf("peak RSS: %ld KiB\n", ru.ru_maxrss);
    printf("bench_slhdsa: %s\n", rc ? "FAIL" : "DONE");
    return rc;
}

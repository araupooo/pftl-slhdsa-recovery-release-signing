# Claim-to-evidence index

Every claim in this pack maps to a runnable script and its unedited
output, or to a pinned primary source. "Shipped" files are the run1/run2
outputs; "fresh-clone-*" files are the independent clean reproduction
(`scripts/clean_reproduce.sh`, comparison in
`outputs/fresh-clone-compare.txt`).

Measured results are labelled **[MEASURED]**; emulated controls are
labelled **[EMULATED]**; design-only statements are labelled
**[DESIGN]**. Anything not executed is listed under Not verified.

## C1 — SLH-DSA sizes match FIPS 205 Table 2 (all twelve pure sets) [MEASURED]

- **Claim.** SLH-DSA-128s: sk 64, pk 32, sig 7,856. 128f: 64 / 32 /
  17,088. 192s: 96 / 48 / 16,224. 192f: 96 / 48 / 35,664. 256s:
  128 / 64 / 29,792. 256f: 128 / 64 / 49,856. SHA2 and SHAKE variants
  of a tuple have identical sizes.
- **Source.** FIPS 205 §11, Table 2 (`docs/citations.md`).
- **Evidence.** `outputs/bench-slhdsa-run1.log`,
  `outputs/bench-slhdsa-run2.log` — every size line ends `OK`
  (36 size lines plus 12 `sizes+roundtrip: OK` lines per log,
  0 `MISMATCH`).
  Reproduction: `outputs/fresh-clone-bench-slhdsa-run1.log`,
  `outputs/fresh-clone-bench-slhdsa-run2.log`.
- **Reproduce.** `bash scripts/build_all.sh && ./work/bench_slhdsa 100 5`
  (binary `src/bench_slhdsa.c`).

## C2 — ML-DSA and Ed25519 sizes match FIPS 204 Table 2 / RFC 8032 [MEASURED]

- **Claim.** ML-DSA-44: sk 2560, pk 1312, sig 2420. ML-DSA-65: sk 4032,
  pk 1952, sig 3309. ML-DSA-87: sk 4896, pk 2592, sig 4627. Ed25519
  public key 32 bytes, signature 64 bytes. These are this pack's own
  re-measurements with the prior pack's harness (reused verbatim), not
  copied numbers.
- **Source.** FIPS 204 §4, Table 2; RFC 8032 §1
  (`docs/citations.md`). The FIPS 204 private-key figures are the
  expanded-form figures (2560 / 4032 / 4896); the smaller figures in
  some secondary write-ups (2528 / 4000 / 4864) are not used.
- **Evidence.** `outputs/bench-sig-run1.log`,
  `outputs/bench-sig-run2.log` — every size line ends `OK`, 0
  `MISMATCH`, 0 verify failures in 100 iterations per scheme per run.
  Reproduction: `outputs/fresh-clone-bench-sig-run1.log`,
  `outputs/fresh-clone-bench-sig-run2.log`.
- **Reproduce.** `bash scripts/build_all.sh && ./work/bench_sig 100`
  (binary `src/bench_sig.c`).

## C3 — SLH-DSA timing (N=100 for 128s/128f, N=5 for 192/256) [MEASURED]

- **Claim.** Two-run mean averages (µs): SLH-DSA-SHA2-128s sign
  744,943.66 / verify 747.00; SHA2-128f sign 35,723.21 / verify
  2,151.41; SHA2-192s sign 1,315,574.61 / verify 1,120.72 (N=5);
  SHA2-192f sign 58,315.74 / verify 3,092.40 (N=5); SHA2-256s sign
  1,163,303.21 / verify 1,593.78 (N=5); SHA2-256f sign 118,484.93 /
  verify 3,170.01 (N=5). SHAKE-128s sign 1,156,342.28 / verify
  1,141.94; SHAKE-128f sign 55,486.11 / verify 3,317.64. Full
  per-run numbers (mean/median/min/max) are in the logs and in
  `docs/decision-memo.md`.
- **Evidence.** `CSV:` lines in `outputs/bench-slhdsa-run1.log` and
  `outputs/bench-slhdsa-run2.log`; reproduction logs as in C1.
  Comparison tolerances (means within 2x for slow/low-N operations)
  are checked by `scripts/compare_reproduce.py`, result in
  `outputs/fresh-clone-compare.txt`.
- **Cross-check.** The published live repo measured SLH-DSA-SHA2-128s
  signing at 547.5 ms (OpenSSL 3.5.9) and cited a liboqs measurement
  of 692.7 ms. This pack's liboqs figure (744.9 ms mean, ~736 ms
  median) agrees in magnitude (~8% above the other liboqs figure, on
  a different machine) and identically in ordering. See
  `docs/decision-memo.md`.
- **Reproduce.** Same as C1.

## C4 — Hybrid baseline timing, re-measured in this pack [MEASURED]

- **Claim.** Two-run mean averages (µs, N=100): Ed25519 sign 56.38 /
  verify 146.33; ML-DSA-44 sign 118.31 / verify 38.00; ML-DSA-65 sign
  184.36 / verify 63.60; ML-DSA-87 sign 184.57 / verify 88.27.
  Hybrid (Ed25519 + ML-DSA-65): signing ~240.74 µs, verification
  ~209.93 µs per release.
- **Evidence.** `CSV:` lines in `outputs/bench-sig-run1.log` and
  `outputs/bench-sig-run2.log`; reproduction logs as in C2.
- **Reproduce.** Same as C2.

## C5 — Recovery installs the release after ML-DSA compromise [MEASURED, compromise EMULATED]

- **Claim.** A hybrid release whose ML-DSA key is revoked is rejected
  by the hybrid verifier, and the SLH-DSA recovery manifest for the
  same artifact and version then installs.
- **Evidence.** Scenarios R2 and R3 in
  `outputs/recovery-scenarios-run1.log` /
  `outputs/run1-recovery-scenarios.csv` (`REJECT ... compromised key:
  pq key mldsa65-rel-a is revoked`, then `VERDICT: ACCEPT`, fallback
  signature `VALID`). Same for run2. Final revocation list
  `outputs/run1-revocation-final.txt` contains `mldsa65-rel-a`.
- **Emulation note.** The compromise is EMULATED by adding the key id
  to the revocation list — exactly the response a real compromise
  would trigger. No key material was leaked; see
  `docs/methodology.md` D6.
- **Reproduce.** `bash scripts/run_all.sh` (drives
  `scripts/run_recovery_scenarios.py`, which calls `src/release.c`
  and `src/recovery.c`).

## C6 — Fallback revocation and rotation [MEASURED]

- **Claim.** A recovery manifest signed by a revoked fallback key is
  rejected; signing the same version with a fresh fallback key id
  installs cleanly.
- **Evidence.** Scenarios R4 and R5 in the scenario logs/CSVs (both
  runs PASS). Final revocation list contains `slhdsa128s-fb-a`;
  final state `outputs/run1-state-final.txt` (`version=4`).
- **Reproduce.** Same as C5.

## C7 — Fallback failure modes reject [MEASURED]

- **Claim.** A corrupt SLH-DSA signature (one byte flipped) is
  rejected by signature verification; a wrong fallback public key is
  rejected by signature verification; a truncated SLH-DSA signature
  is rejected by the FIPS 205 length check.
- **Evidence.** Scenarios R6, R7, R11 in the scenario logs/CSVs
  (both runs PASS). R6/R7/R11 use a separate state file at version 2
  so the signature/length gate — not the rollback gate — rejects;
  the separate state file is printed in the logs (see
  `docs/methodology.md` D8).
- **Reproduce.** Same as C5.

## C8 — Rollback and tampering reject on the recovery path [MEASURED]

- **Claim.** Replaying an older recovery manifest after a newer
  version is installed is rejected (rollback); flipping one payload
  byte is rejected (digest mismatch); editing the recovery manifest
  version after signing is rejected (signature failure).
- **Evidence.** Scenarios R8, R9, R10 in the scenario logs/CSVs
  (both runs PASS).
- **Reproduce.** Same as C5.

## C9 — Corrupt primary signature, recovery installs [MEASURED]

- **Claim.** A hybrid release whose ML-DSA signature is corrupt is
  rejected by the hybrid verifier, and the SLH-DSA recovery manifest
  for the same artifact and version then installs — the recovery path
  works even when the primary signature itself (not just the key) is
  unusable.
- **Evidence.** Scenarios R12a and R12b in the scenario logs/CSVs
  (both runs PASS). The v4 primary keys are fresh rotated keys
  (the old ML-DSA key is revoked), so the rejection is isolated to
  the corrupt signature.
- **Reproduce.** Same as C5.

## C10 — Combined dual-manifest size [MEASURED]

- **Claim.** One JSON manifest carrying all three signatures (Ed25519
  + ML-DSA-65 + SLH-DSA-128s) is 18,273 bytes; the hybrid manifest
  alone is 7,608 bytes and the recovery manifest alone is 10,877
  bytes. Signature bytes alone: 11,229 (64 + 3,309 + 7,856) vs 3,373
  for the hybrid pair.
- **Evidence.** Measurement R-M1 in `outputs/run1-recovery-scenarios.csv`
  and `outputs/run2-recovery-scenarios.csv` (identical value both
  runs); the measured file is `outputs/run1-dual-manifest-v4.json`
  (18,273 bytes) and `outputs/run2-dual-manifest-v4.json`.
- **Reproduce.** Same as C5.

## C11 — SLH-DSA is stateless [DESIGN, source-backed]

- **Claim.** A fallback key needs no per-signature state management:
  each key supports up to 2^64 signatures, and no state file, counter,
  or one-time-key bookkeeping is required for the fallback key.
- **Source.** FIPS 205 §3.1 (`docs/citations.md`).
- **Evidence.** The harness keeps no fallback-key state: `src/recovery.c`
  signs and verifies with no state beyond the key files, and the
  scenario suite signs multiple recovery manifests with the same
  fallback key (R3, R4, R5 use fb-a and fb-b across versions) with no
  state handling. Contrast with stateful LMS/XMSS (SP 800-208), which
  this pack does not implement; see `docs/decision-memo.md` on the
  CNSA 2.0 scoping.

## C12 — No standardised ML-DSA + SLH-DSA composite; dual signing is the construction [DESIGN, source-backed]

- **Claim.** There is no standardised single-algorithm composite of
  ML-DSA and SLH-DSA. The construction in this pack — two independent
  signatures over the same TBS, each verified on its own (AND policy)
  — is dual signing, not a standardised composite, and is presented
  as such everywhere in this pack.
- **Source.** RFC 10073 (composite ML-DSA, verified live 22 Nov 2026):
  it standardises ML-DSA combined with classical schemes only; no
  SLH-DSA composite is defined. `docs/citations.md`.
- **Evidence.** `src/recovery.c` and `src/release.c` sign and verify
  independently; the recovery manifest format
  (`configs/recovery-manifest-format.md`) carries only the fallback
  signature, and the combined dual manifest (R-M1) is a JSON merge of
  two independently signed manifests, not a composite algorithm.

## C13 — Clean reproduction matches shipped numbers [MEASURED]

- **Claim.** A fresh build from the pinned fixtures reproduces the
  shipped headline numbers within tolerance, and all 13 verdict
  scenarios + 1 measurement pass again in both fresh runs.
- **Evidence.** `outputs/fresh-clone-compare.txt`
  (`COMPARISON: ALL CHECKS PASSED`, 146 PASS lines, 0 FAIL), plus
  `outputs/fresh-clone-bench-sig-run*.log`,
  `outputs/fresh-clone-bench-slhdsa-run*.log`, and
  `outputs/fresh-clone-run*-recovery-scenarios.csv`.
- **Reproduce.** `bash scripts/clean_reproduce.sh`.

## C14 — No secret keys in the pack

- **Claim.** No secret key material is present in any shipped file.
- **Evidence.** Shipped manifests contain public keys and signatures
  only; `find pack -name '*.sk'` is empty. Secret keys live only in
  the scratch work directory (`work/recovery-scenarios-run*`), which
  is outside the pack and never published, and are regenerated on
  every run. Verify with `find pack -name '*.sk'` (empty) and
  `bash scripts/verify_digests.sh`.

## Not verified

- **NV1 — Power/EM traces of SLH-DSA signing.** Not measured on this
  VM. The signing operation must happen in a protected (non-shared,
  non-observable) context; the deployment control is the same one the
  ML-DSA literature requires (Zhou et al., TCHES 2025(4); Zhao et al.,
  ePrint 2026/056 — see `docs/citations.md`). SLH-DSA-specific
  leakage was not measured in this pack.
- **NV2 — U-Boot FIT / MCUboot acceptance of SLH-DSA keys.** Not
  verified against a pinned U-Boot or MCUboot version in this pass
  (research report Q6/Q7, still open). The harness demonstrates the
  signing and verification logic in isolation, not inside a bootloader.
- **NV3 — LMS advisories (Sep/Oct 2026).** Reported by a secondary
  survey as fixed only in liboqs 0.17.0; NOT verified against the
  liboqs advisory pages in this pass. Not cited as fact anywhere in
  this pack; LMS/XMSS are discussed only via SP 800-208 and CNSA 2.0.
- **NV4 — Exact on-device recovery path after a fused-root compromise.**
  Silicon-specific; this pack states only the general rule (fuse a
  root that signs short-lived intermediates; keep the release key in
  an HSM with threshold signing), not a per-device procedure.
- **NV5 — HSM / secure-element support for ML-DSA or SLH-DSA
  verification in the bootloader.** Vendor- and silicon-specific; not
  verifiable from public docs alone.
- **NV6 — Draft SP 800-230 2^24-limited SLH-DSA sets.** Experimental
  (initial public draft, Apr 2026); the draft says they must not be
  used in production. Cited, not implemented or measured.
- **NV7 — Cryptographic binding between a recovery manifest and a
  specific hybrid signing event.** Not present by design (see
  `docs/methodology.md` D4): the recovery manifest covers the artifact
  digest, the version, and the fallback key, but not the primary
  signatures. The linkage is operational (same artifact, same version).
- **NV8 — SLH-DSA-192/256 timing statistics.** Measured at N=5 only
  (see `docs/methodology.md` D7). The means are indicative, not tight
  statistics; the size assertions are exact (0 mismatches) and the
  roundtrips pass.

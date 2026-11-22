# Decision memo — SLH-DSA recovery extension for release signing

## Recommendation

**Adopt the SLH-DSA-SHA2-128s recovery path as a recovery-only
fallback, not as a routine signing path: keep signing releases with
hybrid Ed25519 + ML-DSA-65, and ship a separate SLH-DSA-128s recovery
manifest for every release so the release still installs when the
primary ML-DSA key is compromised or the primary signature is corrupt.**

The fallback is justified because its cost is paid where it is cheap
and its benefit lands where it matters:

- **Signing cost is paid once, offline, per release.** SLH-DSA-128s
  signing costs ~745 ms per signature on this machine — 4,041x the
  ML-DSA-65 signing cost — but a release is signed once, by the
  signer, offline. A three-quarter-second signing step in a release
  pipeline is negligible.
- **Verification cost is what the device pays, and it is small.**
  SLH-DSA-128s verification costs ~747 µs — 11.7x the ML-DSA-65
  verification cost, but still under a millisecond, against a firmware
  install step measured in seconds. The recovery verify adds ~0.75 ms
  to an install that already spends ~0.21 ms verifying the hybrid
  signatures.
- **The size cost is real but bounded.** A recovery manifest is
  10,877 bytes (1.43x the 7,608-byte hybrid manifest); a combined
  dual manifest carrying all three signatures is 18,273 bytes (2.40x
  the hybrid manifest). The signature bytes alone are 11,229 bytes
  for all three schemes against 3,373 bytes for the hybrid pair. A
  recovery manifest adds 10,877 bytes to a release — 16.6% of a
  64 KiB firmware image (the combined dual manifest is 27.9% of one);
  for a multi-megabyte image it is noise.
- **The recovery path was demonstrated, not asserted.** 13/13 verdict
  scenarios pass in both runs: the fallback installs the release after
  the ML-DSA key is revoked (R3), after fallback rotation (R5), and
  after the primary signature itself is corrupt (R12b); it rejects a
  revoked fallback key (R4), corrupt/wrong/truncated fallback
  signatures (R6, R7, R11), replay (R8), tampered payload (R9), and a
  tampered version counter (R10).

## Why SLH-DSA-128s, not 128f and not a higher set

Measured on this machine (two-run mean averages; full numbers in
`outputs/bench-slhdsa-run1.log` and `outputs/bench-slhdsa-run2.log`):

| Scheme | pk (B) | sig (B) | sign mean | verify mean |
|---|---|---|---|---|
| SLH-DSA-SHA2-128s | 32 | 7,856 | 744.94 ms | 747.00 µs |
| SLH-DSA-SHA2-128f | 32 | 17,088 | 35.72 ms | 2,151.41 µs |
| SLH-DSA-SHA2-192s (N=5) | 48 | 16,224 | 1,315.57 ms | 1,120.72 µs |
| SLH-DSA-SHA2-192f (N=5) | 48 | 35,664 | 58.32 ms | 3,092.40 µs |
| SLH-DSA-SHA2-256s (N=5) | 64 | 29,792 | 1,163.30 ms | 1,593.78 µs |
| SLH-DSA-SHA2-256f (N=5) | 64 | 49,856 | 118.48 ms | 3,170.01 µs |

- **128s over 128f:** the `f` variant signs ~21x faster (35.7 ms vs
  744.9 ms) but its signature is 2.18x larger (17,088 vs 7,856
  bytes) and its verification is 2.88x slower (2,151 vs 747 µs). A
  recovery path signs rarely and verifies on install, so the `s`
  variant wins on the two costs that matter (size, verify) and loses
  only on the cost that does not matter (one-off signing time).
- **128s over 192s/256s:** the higher sets buy a higher security
  category (3/5 vs 1) at 2.07x–6.35x the signature size (16,224 /
  35,664 / 29,792 / 49,856 bytes vs 7,856), with `s`-variant signing
  times 1.56–1.77x the 128s time and no benefit to the recovery use
  case: the fallback's job is to survive a break of ML-DSA-65
  (category 3), and a category-1 hash-based fallback already rests on
  assumptions independent of ML-DSA's lattice assumptions. Category 1
  is the right match for a fallback to a category-3 primary.
- **SHA2 over SHAKE:** SHA2-128s signs ~36% faster than SHAKE-128s
  (744.9 ms vs 1,156.3 ms) and verifies ~35% faster (747 vs 1,142
  µs) on this machine, at identical sizes. SHA-2 is also the more
  widely available hash in bootloaders. Either family would work; the
  measurements pick SHA2.

## What the primary path still costs (re-measured in this pack)

| Scheme | pk (B) | sig (B) | sign mean (µs) | verify mean (µs) |
|---|---|---|---|---|
| Ed25519 | 32 | 64 | 56.38 | 146.33 |
| ML-DSA-44 | 1,312 | 2,420 | 118.31 | 38.00 |
| ML-DSA-65 | 1,952 | 3,309 | 184.36 | 63.60 |
| ML-DSA-87 | 2,592 | 4,627 | 184.57 | 88.27 |

Hybrid (Ed25519 + ML-DSA-65): signing ~240.74 µs, verification
~209.93 µs per release; combined signature payload 3,373 bytes;
complete signed manifest 7,608 bytes. These are this pack's own
measurements (N=100, two runs, same harness as the prior pack, reused
verbatim); they agree with the prior pack's numbers within a few
percent (prior: ML-DSA-65 sign 167.6 / verify 60.0 µs; Ed25519 sign
57.2 / verify 150.0 µs).

## What was demonstrated (all executed, 13/13 verdicts + 1 measurement, both runs)

- Clean hybrid install accepts (R1); the same flow under rotated
  primary keys accepts (R12a's setup; the hybrid v4 manifest itself is
  rejected only because its ML-DSA signature was deliberately corrupted).
- ML-DSA compromise is handled: revoke the ML-DSA key and the hybrid
  install is rejected (R2); the SLH-DSA recovery manifest for the same
  artifact and version then installs (R3). The compromise is EMULATED
  by revocation — no key material was leaked; see `methodology.md` D6.
- The fallback key is itself revocable and rotatable: revoke it and
  recovery is rejected (R4); rotate to a fresh fallback key and
  recovery installs again (R5).
- A corrupt primary signature does not strand the release: hybrid v4
  with a bit-flipped ML-DSA signature is rejected (R12a), and the
  recovery manifest for v4 installs (R12b).
- The fallback's own failure modes all reject: corrupt SLH-DSA
  signature (R6), wrong fallback public key (R7), truncated SLH-DSA
  signature via the FIPS 205 length check (R11).
- Rollback and tampering still reject on the recovery path: replay of
  v2 after v3 is installed (R8), tampered payload (R9), tampered
  version counter (R10).
- Combined dual-manifest size measured (R-M1): 18,273 bytes for one
  JSON manifest carrying all three signatures (hybrid 7,608 +
  recovery 10,877, minus 312 bytes of shared fields).

Evidence: `outputs/run1-recovery-scenarios.csv`,
`outputs/run2-recovery-scenarios.csv`,
`outputs/recovery-scenarios-run1.log`,
`outputs/recovery-scenarios-run2.log`.

## Cross-check against the published live repo

The published hybrid release-signing pack (live repo HEAD
`2a141f4e`, 20 Nov 2026) measured SLH-DSA-SHA2-128s signing at
547.5 ms (OpenSSL 3.5.9, in-process `openssl speed`) and cited a
liboqs measurement of 692.7 ms. This pack measures 744.9 ms mean
(median ~736 ms) with liboqs 0.16.0. The ordering is identical in all
three stacks (SLH-DSA-128s signing is hundreds of milliseconds;
verification is sub-millisecond), and the magnitudes agree within
~8% between the two liboqs measurements on different machines. The
difference between the OpenSSL and liboqs signing figures is a
toolchain difference, not a contradiction: the same effect was already
observed for ML-DSA signing in the live repo's cross-stack check.

## When the fallback is NOT justified

- **Manifest size budget below ~11 KB per release.** If the update
  channel or the bootloader's manifest buffer cannot carry a
  10,877-byte recovery manifest (or an 18,273-byte dual manifest),
  the fallback does not fit and the primary hybrid manifest alone is
  the answer. Measure the buffer before adopting.
- **No second key lifecycle.** The fallback adds a key that must be
  generated, stored, revoked, and rotated on the same discipline as
  the primary keys. If the organisation cannot operate a second
  revocation list entry and a second rotation procedure, the fallback
  becomes an unmaintained trust anchor — worse than no fallback.
- **NSS / CNSA 2.0 firmware signing.** CNSA 2.0 names LMS/XMSS
  (SP 800-208) for software and firmware signing, not SLH-DSA. For
  NSS use, the fallback should be LMS/XMSS, not SLH-DSA-128s. This
  pack's recommendation is for commercial, non-NSS use.
- **High-frequency signing.** If releases are signed many times per
  minute (not the case for firmware), the ~745 ms signing cost rules
  out 128s; 128f (35.7 ms) would be the fallback variant instead,
  at 2.18x the signature size.

## What this does not claim

- No HSM or secure key storage was used or tested (limitation L3);
  signing keys here are plain files in a scratch directory.
- No firmware was flashed and no bootloader was involved (L4); the
  "install" is the verifier's state-file update on ACCEPT.
- The verifier state file must itself be protected against deletion
  or rollback, or an old signed release would be accepted again (L5).
  This is a deployment requirement, not a harness property.
- The recovery manifest is not cryptographically bound to a specific
  hybrid manifest (L8 / design decision D4); the linkage is
  operational (same artifact, same version).
- U-Boot FIT and MCUboot acceptance of SLH-DSA keys was not verified
  (L10); the harness demonstrates the logic in isolation.
- SLH-DSA-specific side-channel leakage was not measured; the signing
  operation must happen in a protected (non-shared, non-observable)
  context, the same deployment control the ML-DSA literature requires
  (Zhou et al., Zhao et al. — see `citations.md`).

## Migration note

Ship the recovery manifest alongside every hybrid manifest now: same
artifact, same version, one extra file. The verifier already knows
both formats, so enabling the fallback is a policy change (accept a
recovery manifest when the hybrid path fails for a revoked or corrupt
primary), not a format change. Do not sign routine releases with
SLH-DSA alone — the fallback exists for the compromise case, and
routine SLH-DSA signing would pay the 745 ms signing cost and the
7,856-byte signature on every release for no benefit.

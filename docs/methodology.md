# Methodology

## Question

The prior hybrid release-signing pack covers Ed25519 + ML-DSA-65
signing, rollback protection, and compromised-key handling — but it
has no fallback for the day the ML-DSA key itself is compromised. Can a
hash-based SLH-DSA recovery path be added to the same release flow —
same artifact, same version counter, same revocation list — so a
release still installs after the primary key is revoked? What do the
fallback's size and signing cost actually measure, and does the added
fallback justify its size and operational cost?

## Approach

1. **Research first.** Every spec-derived number was checked against a
   primary source before any code was written (see `citations.md`):
   FIPS 205 Table 2 for SLH-DSA sizes, FIPS 204 Table 2 for ML-DSA
   sizes, RFC 8032 §1 for Ed25519 sizes, RFC 10073 for composite
   ML-DSA status, the NIST CSRC PQC project page and NIST IR 8547 for
   migration guidance. The research report that fed this pack flagged
   eight open questions; the ones this pack could answer by measurement
   are answered in the claim index, the rest stay under not-verified.
2. **Pinned stack.** liboqs 0.16.0 built from the SHA-256-verified
   tarball in `fixtures/` (see `SHA256SUMS`); system OpenSSL 3.0.13.
   No network access is needed after the build. The prior pack's
   toolchain, manifest format, revocation format, and version-counter
   policy are reused verbatim — see `docs/reuse.md` for the full reuse
   record, including the discrepancy between the local C-harness prior
   pack and the published live repo.
3. **Harness, not hand-waving.** Two new C programs, plus the two
   reused ones:
   - `src/recovery.c` (new) — `genkey` / `sign` / `verify` for the
     SLH-DSA recovery path. Signs a canonical TBS string (see
     `configs/recovery-manifest-format.md`) with pure SLH-DSA; verify
     checks digest, monotonic version, revocation, FIPS 205 length
     checks, then the fallback signature.
   - `src/bench_slhdsa.c` (new) — SLH-DSA via the liboqs C API
     (`OQS_SIG`); asserts sizes against FIPS 205 Table 2 for all
     twelve pure sets, times keypair/sign/verify (N=100 for the
     128s/128f sets, N=5 for the 192/256 sets — see design decision
     D7), verifies every produced signature.
   - `src/release.c`, `src/bench_sig.c` (reused verbatim) — the prior
     pack's hybrid harness and ML-DSA/Ed25519 bench, re-run here so
     the comparison baseline is measured in this pack, not copied.
4. **Scenario suite.** `scripts/run_recovery_scenarios.py` drives the
   `release` and `recovery` binaries through 13 verdict scenarios
   plus one measurement (R1–R12b, R-M1): clean hybrid install,
   emulated ML-DSA compromise + recovery install, revoked fallback
   key, fallback rotation, corrupt/wrong/truncated fallback
   signatures, replay, tampered payload, tampered version counter,
   corrupt primary signature + recovery install, and the combined
   dual-manifest size. Two full runs (run1, run2) with fresh keys.
5. **Reproduction.** `scripts/clean_reproduce.sh` rebuilds everything
   from the fixtures in a throwaway directory and re-runs the suite;
   `scripts/compare_reproduce.py` checks the fresh numbers against the
   shipped ones (tolerances in that script's header). The comparison
   result is `outputs/fresh-clone-compare.txt`.

## Environment

- VM: 4 CPUs, ~532 MB free RAM at build time, Ubuntu 24.04.
- Toolchain: gcc 13.3.0, cmake 3.28.3, python3 3.12.3, OpenSSL 3.0.13.
- liboqs 0.16.0, optimized build (`OQS_OPT_TARGET=auto`), library only.
- Builds use `-j2` to stay inside the RAM budget.

## What was measured

- `outputs/bench-sig-run1.log`, `outputs/bench-sig-run2.log`:
  ML-DSA-44/65/87 and Ed25519 public-key / secret-key / signature sizes
  against the standard, plus keypair/sign/verify mean, min, max, and
  rate over 100 iterations each (reused baseline harness, re-measured
  in this pack). Machine-readable `CSV:` lines are embedded in the logs.
- `outputs/bench-slhdsa-run1.log`, `outputs/bench-slhdsa-run2.log`:
  SLH-DSA sizes against FIPS 205 Table 2 for all twelve pure sets,
  plus keypair/sign/verify mean, median, min, max, and rate (N=100 for
  128s/128f, N=5 for 192/256), and 0 verify failures.
- `outputs/run1-recovery-scenarios.csv`,
  `outputs/run2-recovery-scenarios.csv`: expected vs observed verdict
  and rejection reason for each of the 13 verdict scenarios, plus the
  R-M1 measurement row; full console logs
  `outputs/recovery-scenarios-run1.log` and
  `outputs/recovery-scenarios-run2.log`.
- `outputs/run1-manifest-hybrid-v*.json`,
  `outputs/run1-manifest-recovery-v*.json`,
  `outputs/run1-firmware-v*.bin`: the signed artifacts and manifests
  from run1 (public keys and signatures only; no secret keys). The same
  set exists for run2. `outputs/run1-dual-manifest-v4.json` is the
  combined manifest carrying all three signatures.

## Design decisions

- **D1 — Pure SLH-DSA, not pre-hash.** The harness signs the TBS bytes
  directly with the pure SLH-DSA variant (FIPS 205). The artifact
  itself is hashed (SHA-256) into the TBS, so the signed data stays
  small and constant-size regardless of artifact size.
- **D2 — SLH-DSA-SHA2-128s as the fallback default.** Category 1,
  smallest signature (7,856 bytes) of any SLH-DSA set, SHA-2 family
  (the most widely available hash in bootloaders). The 128f variant is
  measured alongside it so the size/speed trade-off is a measured
  choice, not an assumed one. See `decision-memo.md`.
- **D3 — Dual signing with an AND policy, not a composite.** There is
  no standardised ML-DSA + SLH-DSA composite algorithm: RFC 10073
  standardises composite ML-DSA with classical schemes only (verified
  live 22 Nov 2026; see `citations.md`). The honest construction is
  two independent signatures over the same TBS, each verified on its
  own. A release installs through the primary path only when both
  primary signatures verify, and through the recovery path only when
  the fallback signature verifies. Neither scheme's validity is
  inferred from the other.
- **D4 — The recovery manifest stands alone.** The recovery manifest
  covers the artifact digest, the version, and the fallback key, but
  it does not carry or bind the primary hybrid signatures. The linkage
  between a recovery manifest and the hybrid release it recovers is
  operational (same artifact bytes, same version number). Binding the
  recovery signature to the hybrid manifest's digest would be a
  hardening, but it would also couple the recovery path to the primary
  path's failure modes — the exact coupling a recovery path should
  avoid. Recorded as limitation L8.
- **D5 — One version counter, one revocation list.** The recovery
  verifier reads and updates the SAME state file and the SAME
  revocation list as the primary verifier. A recovery install advances
  the same monotonic counter, so a later hybrid install must use a
  higher version, and a revoked fallback key is rejected by the same
  mechanism as a revoked primary key.
- **D6 — Compromise is emulated, not real.** No key material was ever
  leaked in this pack. The "compromise" in scenarios R2 and R12 is
  simulated by adding the key id to the revocation list — exactly the
  response a real compromise would trigger — and the scenarios then
  measure what the verifier does with a revoked key. Every scenario
  that depends on this is labelled EMULATED in the claim index.
- **D7 — Iteration counts for slow sets.** SLH-DSA-128s signing costs
  roughly three quarters of a second per signature on this machine
  (measured: ~745 ms mean), and the 192/256 `s` sets cost seconds. The bench therefore runs N=100 for the
  decision-relevant 128s/128f sets and N=5 for the 192/256 sets; the
  iteration count is printed per set, and the comparison script uses a
  2x tolerance for those means. The 192/256 rows exist to prove the
  sizes and that a roundtrip works, not to produce tight statistics.
- **D8 — Version check before revocation check.** Same order as the
  prior pack. Scenarios that test a later gate use a separate state
  file at version 2 (R6, R7, R9, R10, R11), so that the gate under
  test — not the rollback gate — is what rejects the release; each use
  is printed in the logs.
- **D9 — Keys are runtime-only.** Every run generates fresh key pairs
  in the scratch work directory. Secret keys are never written into
  the pack, never committed, and never appear in any log (only
  public-key fingerprints are printed, full SHA-256 in the new
  `recovery genkey` output).

## Limitations

- **L1 — Single machine, single build.** All timings are from one VM
  (4 CPUs, shared host). Absolute microsecond figures are not portable;
  the size figures and the relative ordering of schemes are. The
  clean-reproduction run re-measures on the same class of machine.
- **L2 — Keypair mean is warm-up sensitive.** The first keypair call
  in a process can be much slower (RNG / library warm-up). The
  comparison script therefore checks the keypair *min* within 25% and
  the mean only within 2x; SLH-DSA sign/verify means are checked
  within 2x for the same reason (slow operations, host-load sensitive).
- **L3 — No hardware security module.** Keys are plain files in a
  scratch directory. The harness demonstrates the signing and
  verification logic; it does not demonstrate secure key storage.
  A production deployment must hold signing keys in an HSM or
  equivalent and keep the verifier state file tamper-evident.
- **L4 — No on-device install tested.** The verifier logic (digest,
  version, revocation, signatures) is exercised end to end, but no
  actual firmware was flashed onto a device and no bootloader was
  involved. The "install" here is the state-file update on ACCEPT.
- **L5 — State-file protection is out of scope.** If the verifier's
  state file is deleted or rolled back, an older signed release would
  be accepted again. Protecting that state is a deployment
  requirement; see `configs/version-policy.md`.
- **L6 — SLH-DSA signing is slow.** Roughly three quarters of a
  second per signature for 128s on this machine (measured: ~745 ms
  mean, see the bench logs).
  That cost is paid once per release, offline, by the signer — it
  does not affect verification cost on the device — but it rules out
  SLH-DSA for any high-frequency signing. See `decision-memo.md`.
- **L7 — Timing is wall-clock, not cycle-counted.** No CPU pinning or
  isolation was applied; background load on the shared host can shift
  means between runs. The 2x comparison tolerance for SLH-DSA means
  accounts for this.
- **L8 — No cryptographic binding between recovery and hybrid
  manifests.** See D4. An attacker who can substitute a recovery
  manifest for a different artifact version is stopped by the digest
  and version checks, but the recovery signature itself does not
  attest which primary signing event it recovers.
- **L9 — 192/256 sets measured at N=5.** See D7. Their timing means
  are indicative, not tight statistics; their size assertions are
  exact (0 mismatches) and their roundtrips pass.
- **L10 — No U-Boot FIT or MCUboot integration tested.** Whether a
  bootloader's signature verification accepts SLH-DSA keys was not
  verified in this pass (research report Q6/Q7, still open). The
  harness demonstrates the signing and verification logic in
  isolation, not inside a bootloader.

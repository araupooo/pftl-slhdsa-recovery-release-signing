# SLH-DSA Recovery Extension for Release Signing

A runnable SLH-DSA recovery path for the hybrid release-signing
harness: when the primary hybrid signature (Ed25519 + ML-DSA-65) can no
longer be used — the ML-DSA key was compromised and revoked, or the
primary signature itself is corrupt — a release still installs if it
carries a valid SLH-DSA-128s fallback signature. The fallback key is
itself revocable and rotatable, and the same monotonic version counter
and revocation list apply to both paths. Every measurement in this pack
was produced by running the scripts in this repository; see
`docs/claim-evidence-index.md` for the claim-to-evidence map, and
`docs/decision-memo.md` for the recommendation.

## Quick start (clean reproduction)

```sh
bash scripts/build_all.sh        # build liboqs 0.16.0 + harness binaries into ../work
bash scripts/run_all.sh          # bench (2 runs) + recovery scenarios (2 runs) -> outputs/
bash scripts/verify_digests.sh   # verify SHA256SUMS
bash scripts/clean_reproduce.sh  # full rebuild + rerun in a temp dir, compare headline numbers
```

Requirements: cmake, gcc, python3, OpenSSL 3.0.13. The build uses `-j2`
(the reference VM has 4 CPUs and tight RAM). The full suite takes
~10 minutes; the clean reproduction takes ~20 minutes (SLH-DSA-128s
signing costs roughly three quarters of a second per signature).

## Layout

- `scripts/` — `build_all.sh`, `run_all.sh`, `clean_reproduce.sh`,
  `compare_reproduce.py`, `verify_digests.sh`, `make_sha256sums.sh`,
  `run_recovery_scenarios.py`.
- `src/` — `recovery.c` (`genkey` / `sign` / `verify` for the SLH-DSA
  recovery path), `bench_slhdsa.c` (SLH-DSA sizes vs FIPS 205 Table 2,
  timing), `release.c` (hybrid harness, reused verbatim from the prior
  pack), `bench_sig.c` (ML-DSA + Ed25519 bench, reused verbatim).
- `configs/` — release-manifest format, recovery-manifest format,
  revocation-list format, monotonic version-counter policy.
- `docs/` — `methodology.md`, `decision-memo.md`,
  `claim-evidence-index.md`, `citations.md`, `reuse.md`,
  `EXCERPTS.md`, `index.html` (results table, numbers match the logs).
- `fixtures/` — pinned liboqs 0.16.0 source tarball (SHA-256 verified).
- `outputs/` — unedited logs, scenario CSVs, signed artifacts and
  manifests, final state/revocation files, `fresh-clone-compare.txt`.

## Harness entry point

`scripts/run_all.sh` is the entry point: it runs both benches and the
recovery scenario suite and writes every output under `outputs/`. The
recovery harness itself is `src/recovery.c` (`recovery genkey|sign|verify`);
the primary harness is `src/release.c` (`release genkey|sign|verify`).

## Headline results

See `docs/index.html` and `docs/decision-memo.md`. In brief:

- **Recovery works:** 13/13 verdict scenarios PASS in both runs
  (clean hybrid install; ML-DSA compromise + SLH-DSA recovery install;
  revoked fallback key rejects; fallback rotation restores installs;
  corrupt/wrong/truncated fallback signatures reject; replay,
  tampered payload, and tampered version counter reject; corrupt
  primary signature rejects while the recovery manifest installs).
- **SLH-DSA-128s costs:** signature 7,856 bytes; signing ~744.9 ms
  (mean, N=100, two runs); verification ~747 µs. The signing cost is
  paid once, offline, per release; verification is under a millisecond.
- **128s over 128f:** the `f` variant signs ~21x faster (35.7 ms)
  but its signature is 2.18x larger (17,088 bytes) and verification is
  2.88x slower (2,151 µs). For a recovery path that signs rarely and
  verifies on install, 128s is the right choice.
- **Manifest sizes (measured):** hybrid 7,608 bytes; recovery 10,877
  bytes; combined dual manifest (all three signatures) 18,273 bytes.
- **Sizes match the standards exactly:** all twelve SLH-DSA sets match
  FIPS 205 Table 2, all three ML-DSA sets match FIPS 204 Table 2,
  Ed25519 matches RFC 8032 — 0 mismatches in every run.
- **Recommendation:** adopt SLH-DSA-SHA2-128s as a recovery-only
  fallback (not for routine signing), for commercial, non-NSS use.
  CNSA 2.0 names LMS/XMSS for firmware signing, not SLH-DSA.

## Keys

All keys are generated at runtime by the harness and live only in the
scratch work directory; they are never committed. Shipped files contain
only public keys and signatures (inside the manifests). The "compromise"
in the scenarios is emulated by revocation — no key material was ever
leaked; see `docs/methodology.md`.

## Reproduction

`scripts/clean_reproduce.sh` rebuilds everything from the fixtures in
a throwaway directory, re-runs the full suite, and compares the
re-derived headline numbers against the shipped ones. The comparison
result is `outputs/fresh-clone-compare.txt`:
`COMPARISON: ALL CHECKS PASSED` (146 PASS lines, 0 FAIL).

# Reuse record — what this pack took from the prior release-signing work

## The discrepancy, stated first

There are TWO prior release-signing packs, and they are not the same
pack:

1. **The local C-harness pack** — built 12 Nov 2026, 67 files,
   PACK-READY 12 Nov ~22:40 WIB, **never published**. Local copy:
   `task-586610c5/pack/` (relative to the task folder this pack was
   built in). It is a C harness: `src/release.c` (hybrid
   Ed25519 + ML-DSA sign/verify with monotonic version counter and
   revocation list), `src/bench_sig.c`, 11 scenarios, all passing.
   Its PACK-READY.md states: "Built locally only. No repo created,
   nothing submitted."
2. **The published live repo** —
   https://github.com/araupooo/pftl-hybrid-release-signing-evidence-pack —
   HEAD `2a141f4e397ffdabcce15ebbd2557fccc3ace0f7`, "Add fresh-clone
   reproduction log and updated hashes", pushed 2026-11-20T15:09:23Z,
   131 files. It is a DIFFERENT implementation of the same topic: a
   shell/OpenSSL-3.5.9 harness (`scripts/dual_sign_demo.sh`,
   `scripts/downgrade_sim.sh`, `scripts/compromise_drill.sh`,
   `scripts/bench_openssl.sh`) with no C code, no `src/` directory,
   and a different manifest format. It already contains SLH-DSA timing
   measurements for all twelve sets and a recommendation to keep
   SLH-DSA-128s as a fallback.

This pack is built on the **local C-harness pack (1)**, because it is
the runnable, state-machine-verified baseline (real monotonic counter,
real revocation list, real key rotation) and because its toolchain
(liboqs 0.16.0) builds on this machine, while the live repo's harness
provisions OpenSSL 3.5.9, which this VM does not provide (system
OpenSSL is 3.0.13, which has no ML-DSA). The live repo (2) is used as a
**cross-check source only**: its SLH-DSA timing claims are the
independent numbers this pack's liboqs measurements are compared
against (see `docs/claim-evidence-index.md`, C3), and its
recommendation is the starting point this pack tests with a runnable
recovery path rather than re-stating.

A third related pack is cited by the live repo for liboqs SLH-DSA
timings:
https://github.com/araupooo/postfiat-release-signing-pqc-assessment —
HEAD `aef7ab057c076dd745e26120f71bc7e598aa2324`, "Upload evidence pack:
sources files". It is a cross-check source only; nothing was copied
from it.

## What was reused verbatim from the local C-harness pack

| File in this pack | Source | Change |
|---|---|---|
| `src/release.c` | local pack `src/release.c` | None. Byte-identical. |
| `src/bench_sig.c` | local pack `src/bench_sig.c` | None. Byte-identical. |
| `configs/manifest-format.md` | local pack `configs/manifest-format.md` | None. |
| `configs/revocation-format.md` | local pack `configs/revocation-format.md` | None. |
| `configs/version-policy.md` | local pack `configs/version-policy.md` | None. |
| `fixtures/liboqs-0.16.0.tar.gz` | local pack `fixtures/liboqs-0.16.0.tar.gz` | None. SHA-256 verified on copy: `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`. |

## What was adapted

| File in this pack | Source | Change |
|---|---|---|
| `scripts/build_all.sh` | local pack `scripts/build_all.sh` | Builds four binaries now (`bench_sig`, `bench_slhdsa`, `release`, `recovery`) instead of two. |
| `scripts/run_all.sh` | local pack `scripts/run_all.sh` | Adds `bench_slhdsa` (run1+run2) and the recovery scenario suite (run1+run2). |
| `scripts/clean_reproduce.sh` | local pack `scripts/clean_reproduce.sh` | Temp-dir prefix changed; runtime note updated (~20 min). |
| `scripts/compare_reproduce.py` | local pack `scripts/compare_reproduce.py` | Extended: SLH-DSA bench checks (loose timing tolerances for slow/low-N sets), recovery scenario checks (13 verdicts + 1 measurement per run, R-M1 exact match). |
| `scripts/verify_digests.sh` | local pack `scripts/verify_digests.sh` | None. |
| `scripts/make_sha256sums.sh` | local pack `scripts/make_sha256sums.sh` | None. |

## What is new in this pack

- `src/recovery.c` — SLH-DSA recovery signing/verification harness
  (`genkey` / `sign` / `verify`), format `recovery-release-manifest/1`.
- `src/bench_slhdsa.c` — SLH-DSA size and timing bench, all twelve pure
  sets, sizes asserted against FIPS 205 Table 2.
- `configs/recovery-manifest-format.md` — the recovery manifest format.
- `scripts/run_recovery_scenarios.py` — 13 verdict scenarios + 1
  measurement (R1–R12b, R-M1).
- `docs/decision-memo.md` — updated recommendation for the fallback.
- `docs/claim-evidence-index.md`, `docs/methodology.md`,
  `docs/citations.md`, `docs/EXCERPTS.md`, `docs/index.html` — written
  for this pack (the prior pack's docs were read, not copied, except
  where a section is explicitly marked as carried over).

## Small deliberate changes from the prior pack

- `recovery genkey` prints the FULL 64-character SHA-256 fingerprint of
  the public key. The prior pack's `release genkey` prints only the
  first 16 hex characters; this pack keeps that behaviour in the reused
  `release` binary (verbatim reuse) but does not repeat the truncation
  in new code.
- The prior pack's decision memo recommended hybrid Ed25519 + ML-DSA-65
  now. This pack keeps that recommendation for the primary path and
  adds a separate, evidence-backed recommendation for the SLH-DSA
  recovery path; see `docs/decision-memo.md`.

## Prior ML-DSA results reused as the comparison baseline

The prior local pack measured (N=100, means averaged over run1/run2):
Ed25519 sign 57.2 µs / verify 150.0 µs; ML-DSA-44 sign 111.8 / verify
36.3; ML-DSA-65 sign 167.6 / verify 60.0; ML-DSA-87 sign 201.4 /
verify 92.3. This pack re-measures the same schemes with the same
harness (`src/bench_sig.c`, verbatim) in its own runs; the comparison
table in `docs/decision-memo.md` uses THIS pack's measured numbers,
with the prior pack's numbers cited as the cross-check.

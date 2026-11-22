# Run manifest

## Runs

- **run1 / run2** — `bash scripts/run_all.sh`, 22 Nov 2026, ~01:49–01:58 UTC.
  Machine: 4-CPU VM, Ubuntu 24.04, gcc 13.3.0, cmake 3.28.3,
  python3 3.12.3, OpenSSL 3.0.13. liboqs 0.16.0, optimized build
  (`OQS_OPT_TARGET=auto`), built from `fixtures/liboqs-0.16.0.tar.gz`
  (SHA-256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`).
- **fresh-clone-run1 / fresh-clone-run2** — `bash scripts/clean_reproduce.sh`,
  same machine, throwaway workdir (removed on exit). Comparison in
  `outputs/fresh-clone-compare.txt`.

## What each run produced

- `bench-sig-run*.log` — ML-DSA-44/65/87 + Ed25519 sizes vs FIPS 204
  Table 2 / RFC 8032, timing N=100, 0 verify failures.
- `bench-slhdsa-run*.log` — all twelve pure SLH-DSA sets, sizes vs
  FIPS 205 Table 2, timing N=100 (128s/128f) / N=5 (192/256),
  0 verify failures.
- `recovery-scenarios-run*.log`, `run*-recovery-scenarios.csv` —
  13 verdict scenarios + 1 measurement, 14/14 rows PASS per run.
- `run*-manifest-hybrid-v*.json`, `run*-manifest-recovery-v*.json`,
  `run*-firmware-v*.bin`, `run*-dual-manifest-v4.json`,
  `run*-revocation-final.txt`, `run*-state-final.txt`.

## Notes

- The scenario CSVs use the Python csv module's default line ending
  (CRLF), the same as the prior pack's CSVs. `csv.DictReader` and the
  comparison script handle it; the human-readable logs use LF.
- The clean-reproduction comparison result is in
  `outputs/fresh-clone-compare.txt` (see `docs/claim-evidence-index.md`
  C13).

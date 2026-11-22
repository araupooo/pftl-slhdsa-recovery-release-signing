# Excerpts

Short verbatim excerpts from the pack's unedited logs and docs. Each
excerpt is quoted exactly as it appears in its source file.

## Headline recommendation (docs/decision-memo.md)

> Adopt the SLH-DSA-SHA2-128s recovery path as a recovery-only
> fallback, not as a routine signing path: keep signing releases with
> hybrid Ed25519 + ML-DSA-65, and ship a separate SLH-DSA-128s recovery
> manifest for every release so the release still installs when the
> primary ML-DSA key is compromised or the primary signature is corrupt.

## SLH-DSA-128s bench (outputs/bench-slhdsa-run1.log)

> SLH-DSA-SHA2-128s sign       n=100   mean=   758316.58 us  median=   744988.93 us  min=   720089.13 us  max=   912932.84 us  rate=     1.32 ops/s
> SLH-DSA-SHA2-128s verify     n=100   mean=      764.17 us  median=      737.74 us  min=      662.27 us  max=     1174.00 us  rate=  1308.62 ops/s
> [SLH-DSA-SHA2-128s] sizes+roundtrip: OK

## Hybrid baseline bench (outputs/bench-sig-run1.log)

> CSV: ML-DSA-65 sign,n=100,mean_us=173.96,min_us=71.61,max_us=631.64,rate_ops_s=5748.31
> CSV: ML-DSA-65 verify,n=100,mean_us=63.17,min_us=57.37,max_us=453.76,rate_ops_s=15830.83

## Recovery scenarios (outputs/recovery-scenarios-run1.log)

> run_recovery_scenarios: 14/14 rows PASS (13 verdict scenarios + 1 measurement)
> run_recovery_scenarios: DONE

> SCENARIO R2 revoked-mldsa-key-hybrid-v2 EXPECTED=REJECT OBSERVED=REJECT REASON=compromised key: pq key mldsa65-rel-a is revoked RESULT=PASS
> SCENARIO R3 recovery-install-v2-fallback-a EXPECTED=ACCEPT OBSERVED=ACCEPT REASON=artifact digest, monotonic version, revocation, lengths, and fallback signature valid RESULT=PASS
> SCENARIO R12b recovery-install-v4-after-corrupt-primary EXPECTED=ACCEPT OBSERVED=ACCEPT REASON=artifact digest, monotonic version, revocation, lengths, and fallback signature valid RESULT=PASS
> MEASUREMENT R-M1 combined-dual-manifest-size VALUE=18273 bytes (hybrid 7608 + recovery 10877) REASON=byte size of one JSON manifest carrying all three signatures

## Clean reproduction (outputs/fresh-clone-compare.txt)

> PASS recovery scenarios run1 R-M1 combined-manifest size identical shipped=18273 bytes (hybrid 7608 + recovery 10877) fresh=18273 bytes (hybrid 7608 + recovery 10877)
> COMPARISON: ALL CHECKS PASSED

Reproduction command and result:

```sh
bash scripts/clean_reproduce.sh   # full rebuild + rerun in a temp dir
# clean_reproduce: exit 0
# COMPARISON: ALL CHECKS PASSED (146 PASS lines, 0 FAIL)
```

## Manifest sizes (measured, run1 = run2)

- Hybrid manifest (Ed25519 + ML-DSA-65): 7,608 bytes
  (`outputs/run1-manifest-hybrid-v4.json`)
- Recovery manifest (SLH-DSA-SHA2-128s): 10,877 bytes
  (`outputs/run1-manifest-recovery-v4.json`)
- Combined dual manifest (all three signatures): 18,273 bytes
  (`outputs/run1-dual-manifest-v4.json`)

## Measured vs emulated (explicit separation)

- **Measured:** all sizes and timings in the bench logs; all 13
  verdict scenarios (real signatures, real verification, real
  revocation-list and state-file behaviour).
- **Emulated:** the key compromise in scenarios R2 and R12 — simulated
  by adding the key id to the revocation list. No key material was
  ever leaked. See `docs/methodology.md` D6.
- **Design-only:** no standardised ML-DSA + SLH-DSA composite exists,
  so the construction is dual signing with an AND policy (see
  `docs/claim-evidence-index.md` C12); the recovery manifest is not
  cryptographically bound to a specific hybrid manifest (NV7).

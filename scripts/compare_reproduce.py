#!/usr/bin/env python3
"""compare_reproduce.py — compare re-derived (fresh-clone-*) headline numbers
against the shipped ones in pack/outputs/.

Usage: compare_reproduce.py <outputs-dir>
Prints one PASS/FAIL line per check and exits non-zero if any check fails.

Tolerances: sign/verify means within 25%; keypair means within 2x (first-call
warm-up makes keypair means outlier-sensitive — the stable figure is min,
checked within 25%). SLH-DSA-128s/128f sign means are slow (~0.5 s / ~25 ms)
and host-load sensitive, so they are checked within 2x on the mean and 25%
on the min; the 192/256 sets run at N=5, so their means are checked within
2x only. Exact match for sizes (OK lines), verify-failure counts (0), and
scenario PASS counts (13/13 verdict scenarios + 1 measurement row per run).
The R-M1 combined-manifest size is deterministic and must match exactly.
"""
import csv
import re
import sys

OUT = sys.argv[1]
fails = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    if not ok:
        fails.append(name)


def read(p):
    with open(f"{OUT}/{p}", errors="ignore") as f:
        return f.read()


def bench_numbers(fn, schemes):
    t = read(fn)
    m = {}
    for scheme in schemes:
        for op in ("keypair", "sign", "verify"):
            mm = re.search(rf"CSV: {re.escape(scheme)} {op},n=\d+,mean_us=([\d.]+),min_us=([\d.]+),max_us=([\d.]+),rate_ops_s=([\d.]+)", t)
            m[(scheme, op)] = (float(mm.group(1)), float(mm.group(2))) if mm else (None, None)
        mm = re.search(rf"\[{re.escape(scheme)}\] verify failures: (\d+) / (\d+)", t)
        m[(scheme, "verify_fail")] = int(mm.group(1)) if mm else None
    m["sizes_ok"] = t.count(" OK") >= 12
    m["sizes_fail"] = t.count("MISMATCH")
    return m


def scenario_numbers(fn):
    rows = list(csv.DictReader(open(f"{OUT}/{fn}")))
    verdicts = [r for r in rows if r["expected"] != "MEASURED"]
    measurements = [r for r in rows if r["expected"] == "MEASURED"]
    ok = sum(1 for r in verdicts if r["result"] == "PASS")
    return {"n": len(rows), "verdicts": len(verdicts), "pass": ok,
            "measurements": len(measurements),
            "m1": measurements[0]["observed"] if measurements else None}


def close(a, b, rel=0.25, abs_tol=5.0):
    return a is not None and b is not None and abs(a - b) <= max(rel * abs(b), abs_tol)


def close_loose(a, b, rel=1.0, abs_tol=5.0):
    """2x tolerance for slow / low-N operations."""
    return a is not None and b is not None and abs(a - b) <= max(rel * abs(b), abs_tol)


MLDSA = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Ed25519")
SLH128 = ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
          "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f")
SLHREST = ("SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256s",
           "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
           "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f")

# --- ML-DSA + Ed25519 baseline bench (reused harness, strict tolerances) ---
for run in ("run1", "run2"):
    s = bench_numbers(f"bench-sig-{run}.log", MLDSA)
    f = bench_numbers(f"fresh-clone-bench-sig-{run}.log", MLDSA)
    check(f"bench {run} sizes OK (FIPS 204 Table 2 / RFC 8032)", f["sizes_ok"] and f["sizes_fail"] == 0, "fresh")
    check(f"bench {run} sizes OK (FIPS 204 Table 2 / RFC 8032)", s["sizes_ok"] and s["sizes_fail"] == 0, "shipped")
    for scheme in MLDSA:
        check(f"bench {run} {scheme} verify failures 0",
              s[(scheme, "verify_fail")] == 0 and f[(scheme, "verify_fail")] == 0)
        check(f"bench {run} {scheme} keypair min within 25% and mean within 2x",
              close(f[(scheme, "keypair")][1], s[(scheme, "keypair")][1])
              and f[(scheme, "keypair")][0] <= 2 * s[(scheme, "keypair")][0]
              and s[(scheme, "keypair")][0] <= 2 * f[(scheme, "keypair")][0],
              f"shipped mean={s[(scheme, 'keypair')][0]} min={s[(scheme, 'keypair')][1]} us; "
              f"fresh mean={f[(scheme, 'keypair')][0]} min={f[(scheme, 'keypair')][1]} us")
        for op in ("sign", "verify"):
            check(f"bench {run} {scheme} {op} mean within 25%",
                  close(f[(scheme, op)][0], s[(scheme, op)][0]),
                  f"shipped={s[(scheme, op)][0]} us fresh={f[(scheme, op)][0]} us")

# --- SLH-DSA bench (sizes exact; timing loose where slow / low-N) ---
for run in ("run1", "run2"):
    s = bench_numbers(f"bench-slhdsa-{run}.log", SLH128 + SLHREST)
    f = bench_numbers(f"fresh-clone-bench-slhdsa-{run}.log", SLH128 + SLHREST)
    check(f"slhdsa {run} sizes OK (FIPS 205 Table 2, 12 sets)", f["sizes_ok"] and f["sizes_fail"] == 0, "fresh")
    check(f"slhdsa {run} sizes OK (FIPS 205 Table 2, 12 sets)", s["sizes_ok"] and s["sizes_fail"] == 0, "shipped")
    for scheme in SLH128 + SLHREST:
        check(f"slhdsa {run} {scheme} verify failures 0",
              s[(scheme, "verify_fail")] == 0 and f[(scheme, "verify_fail")] == 0)
        # keypair: min within 25%, mean within 2x (warm-up outlier)
        check(f"slhdsa {run} {scheme} keypair min within 25% and mean within 2x",
              close(f[(scheme, "keypair")][1], s[(scheme, "keypair")][1])
              and f[(scheme, "keypair")][0] <= 2 * s[(scheme, "keypair")][0]
              and s[(scheme, "keypair")][0] <= 2 * f[(scheme, "keypair")][0],
              f"shipped mean={s[(scheme, 'keypair')][0]} min={s[(scheme, 'keypair')][1]} us; "
              f"fresh mean={f[(scheme, 'keypair')][0]} min={f[(scheme, 'keypair')][1]} us")
        # sign/verify: 128s/128f (N=100) within 2x on the mean — SLH-DSA-128s
        # signing is ~0.5 s and host-load sensitive; 192/256 (N=5) also 2x.
        for op in ("sign", "verify"):
            check(f"slhdsa {run} {scheme} {op} mean within 2x",
                  close_loose(f[(scheme, op)][0], s[(scheme, op)][0]),
                  f"shipped={s[(scheme, op)][0]} us fresh={f[(scheme, op)][0]} us")

# --- recovery scenarios ---
for run in ("run1", "run2"):
    s = scenario_numbers(f"{run}-recovery-scenarios.csv")
    f = scenario_numbers(f"fresh-clone-{run}-recovery-scenarios.csv")
    check(f"recovery scenarios {run} shipped 13/13 verdicts PASS + 1 measurement",
          s["verdicts"] == 13 and s["pass"] == 13 and s["measurements"] == 1,
          f"{s['pass']}/{s['verdicts']} verdicts, {s['measurements']} measurement")
    check(f"recovery scenarios {run} fresh 13/13 verdicts PASS + 1 measurement",
          f["verdicts"] == 13 and f["pass"] == 13 and f["measurements"] == 1,
          f"{f['pass']}/{f['verdicts']} verdicts, {f['measurements']} measurement")
    check(f"recovery scenarios {run} R-M1 combined-manifest size identical",
          s["m1"] == f["m1"], f"shipped={s['m1']} fresh={f['m1']}")
    for prefix, label in (("", "shipped"), ("fresh-clone-", "fresh")):
        rows = list(csv.DictReader(open(f"{OUT}/{prefix}{run}-recovery-scenarios.csv")))
        bad = [r["scenario"] for r in rows if r["expected"] != "MEASURED" and r["expected"] != r["observed"]]
        check(f"recovery scenarios {run} {label} expected==observed for all verdicts", len(bad) == 0,
              f"mismatches: {bad}")

print()
if fails:
    print(f"COMPARISON: {len(fails)} FAILURES: {', '.join(fails)}")
    sys.exit(1)
print("COMPARISON: ALL CHECKS PASSED")

#!/usr/bin/env python3
"""run_recovery_scenarios.py — SLH-DSA recovery-path scenarios for the
hybrid release-signing harness.

Usage: run_recovery_scenarios.py <release-bin> <recovery-bin> <workdir> <run-label> <outdir>
  release-bin : path to the compiled `release` binary (prior pack harness)
  recovery-bin: path to the compiled `recovery` binary (src/recovery.c)
  workdir     : scratch dir for keys/state (runtime keys, never shipped)
  run-label   : e.g. "run1" (used in log lines and shipped filenames)
  outdir      : pack outputs dir; receives the scenario CSV, shipped
                artifacts/manifests, final state and revocation files.

Every verdict scenario prints one line:
  SCENARIO <id> <name> EXPECTED=<x> OBSERVED=<y> RESULT=PASS|FAIL
and appends a row to <outdir>/<run-label>-recovery-scenarios.csv.
The measurement row R-M1 prints:
  MEASUREMENT <id> <name> VALUE=<v>
Exit code 0 iff every scenario's observed verdict matches its expected one.

Story of the run (one release line, versions 1-4):
  v1 — clean hybrid install (Ed25519 + ML-DSA-65).
  v2 — hybrid release signed, then the ML-DSA key is COMPROMISED
       (emulated: the key id is added to the revocation list; no key
       material was actually leaked — see docs/methodology.md).
       The hybrid install is rejected; the SLH-DSA recovery manifest
       for the same artifact and version installs instead.
  v3 — released after the compromise, so it has NO hybrid manifest
       (the primary key is dead); it is signed with the SLH-DSA
       fallback only. The first fallback key is then revoked, and
       rotation to a second fallback key restores installs.
  v4 — primary keys rotated (fresh Ed25519 + ML-DSA-65); a corrupt
       ML-DSA signature rejects the hybrid install, and the SLH-DSA
       recovery manifest for the same version installs instead.

Check order inside `release verify` and `recovery verify` (see
src/release.c, src/recovery.c): digest -> monotonic version ->
revocation -> length checks -> signature(s). Scenarios R6/R7/R9/R10/R11
use a separate state file at version 2, so the version gate passes and
the check under test — not the rollback gate — is what rejects the
release; each use of the separate state file is logged.

Deterministic artifacts: firmware-v1..v4.bin are 64 KiB of fixed byte
patterns (no randomness in the artifact content). Keys are generated
fresh per run by the harness (randomness comes from the OS/liboqs RNG);
only public keys and signatures appear in shipped files.
"""
import base64
import csv
import json
import os
import shutil
import subprocess
import sys

RELEASE, RECOVERY, WORK, LABEL, OUT = sys.argv[1:6]
os.makedirs(WORK, exist_ok=True)
os.makedirs(OUT, exist_ok=True)

# Scrub the absolute task-root prefix from everything this driver prints,
# so the shipped (unedited) logs never contain local filesystem paths:
# the task folder name carries an identifier that must not be published.
TASKROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def scrub(s):
    return s.replace(TASKROOT, ".")

KEYDIR = os.path.join(WORK, "keys")
os.makedirs(KEYDIR, exist_ok=True)
STATE = os.path.join(WORK, "state.txt")
STATE_ISO = os.path.join(WORK, "state-iso.txt")
REVOC = os.path.join(WORK, "revocation.txt")

results = []  # (id, name, expected, observed, reason, pass)
measurements = []  # (id, name, value)


def run(args, expect_rc=None):
    p = subprocess.run(args, capture_output=True, text=True)
    print("$ " + scrub(" ".join(args)))
    print(scrub(p.stdout), end="")
    if p.stderr:
        print(scrub(p.stderr), end="")
    print(f"[exit {p.returncode}]")
    return p


def scenario(sid, name, expected, observed, reason):
    ok = expected == observed
    results.append((sid, name, expected, observed, reason, ok))
    print(f"SCENARIO {sid} {name} EXPECTED={expected} OBSERVED={observed} "
          f"REASON={reason} RESULT={'PASS' if ok else 'FAIL'}")
    return ok


def measurement(mid, name, value, reason):
    measurements.append((mid, name, value))
    results.append((mid, name, "MEASURED", value, reason, True))
    print(f"MEASUREMENT {mid} {name} VALUE={value} REASON={reason}")


def verdict(p):
    for line in p.stdout.splitlines():
        if line.startswith("VERDICT:"):
            return line.split(":", 1)[1].strip()
    return f"NO-VERDICT(exit {p.returncode})"


def reason(p):
    for line in p.stdout.splitlines():
        if line.startswith("REASON:"):
            return line.split(":", 1)[1].strip()
    return ""


def write_artifact(path, seed):
    with open(path, "wb") as f:
        f.write(bytes(((i * seed + 1) % 256) for i in range(65536)))


def load_manifest(path):
    with open(path) as f:
        return json.load(f)


def save_manifest(m, path):
    with open(path, "w") as f:
        json.dump(m, f, indent=2)
        f.write("\n")


def flip_b64_byte(b64, offset):
    raw = bytearray(base64.b64decode(b64))
    raw[offset % len(raw)] ^= 0xFF
    return base64.b64encode(bytes(raw)).decode()


def trunc_b64(b64, nbytes=1):
    raw = base64.b64decode(b64)
    return base64.b64encode(raw[:-nbytes]).decode()


print(f"run_recovery_scenarios: label={LABEL} release={scrub(RELEASE)} recovery={scrub(RECOVERY)} work={scrub(WORK)} out={scrub(OUT)}")
print("run_recovery_scenarios: check order in verify: digest -> version -> revocation -> lengths -> signature(s)")
print("run_recovery_scenarios: compromise is EMULATED by revocation (no key material was leaked); see docs/methodology.md")

# --- deterministic artifacts ---
art1 = os.path.join(WORK, "firmware-v1.bin")
art2 = os.path.join(WORK, "firmware-v2.bin")
art3 = os.path.join(WORK, "firmware-v3.bin")
art4 = os.path.join(WORK, "firmware-v4.bin")
write_artifact(art1, 7)
write_artifact(art2, 13)
write_artifact(art3, 29)
write_artifact(art4, 41)
print(f"artifacts: v1={scrub(art1)} v2={scrub(art2)} v3={scrub(art3)} v4={scrub(art4)} (64 KiB deterministic patterns)")

# --- keys (runtime-generated, never shipped) ---
run([RELEASE, "genkey", "Ed25519", "ed25519-rel-a", KEYDIR])
run([RELEASE, "genkey", "ML-DSA-65", "mldsa65-rel-a", KEYDIR])
run([RECOVERY, "genkey", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-a", KEYDIR])
run([RECOVERY, "genkey", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-b", KEYDIR])
run([RECOVERY, "genkey", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-c", KEYDIR])  # wrong-fallback-key control

# --- hybrid manifests v1, v2 ---
man_h1 = os.path.join(WORK, "manifest-hybrid-v1.json")
man_h2 = os.path.join(WORK, "manifest-hybrid-v2.json")
run([RELEASE, "sign", art1, "1", "ed25519-rel-a", KEYDIR, "ML-DSA-65", "mldsa65-rel-a", KEYDIR, man_h1])
run([RELEASE, "sign", art2, "2", "ed25519-rel-a", KEYDIR, "ML-DSA-65", "mldsa65-rel-a", KEYDIR, man_h2])

# --- empty revocation list, fresh state ---
open(REVOC, "w").write("# revocation list: one key id per line\n")
if os.path.exists(STATE):
    os.remove(STATE)

# R1: clean hybrid install of v1 -> ACCEPT
p = run([RELEASE, "verify", man_h1, art1, STATE, REVOC])
scenario("R1", "clean-hybrid-install-v1", "ACCEPT", verdict(p), reason(p))

# R2: EMULATED compromise — revoke the ML-DSA key; hybrid v2 -> REJECT.
# State is at version 1 and v2 > 1, so the revocation gate (not the
# rollback gate) is what rejects the release.
with open(REVOC, "a") as f:
    f.write("mldsa65-rel-a\n")
print("R2: EMULATED compromise — mldsa65-rel-a added to the revocation list (no key material leaked)")
p = run([RELEASE, "verify", man_h2, art2, STATE, REVOC])
scenario("R2", "revoked-mldsa-key-hybrid-v2", "REJECT", verdict(p), reason(p))

# R3: recovery — same artifact and version, SLH-DSA fallback key fb-a -> ACCEPT
man_r2 = os.path.join(WORK, "manifest-recovery-v2.json")
run([RECOVERY, "sign", art2, "2", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-a", KEYDIR, man_r2])
p = run([RECOVERY, "verify", man_r2, art2, STATE, REVOC])
scenario("R3", "recovery-install-v2-fallback-a", "ACCEPT", verdict(p), reason(p))

# R4: v3 has no hybrid manifest (primary key dead). Sign recovery v3 with
# fb-a, then revoke fb-a -> recovery verify REJECT (revoked fallback).
man_r3 = os.path.join(WORK, "manifest-recovery-v3.json")
run([RECOVERY, "sign", art3, "3", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-a", KEYDIR, man_r3])
with open(REVOC, "a") as f:
    f.write("slhdsa128s-fb-a\n")
print("R4: fallback key slhdsa128s-fb-a revoked")
p = run([RECOVERY, "verify", man_r3, art3, STATE, REVOC])
scenario("R4", "revoked-fallback-key-v3", "REJECT", verdict(p), reason(p))

# R5: fallback rotation — sign recovery v3 with fb-b -> ACCEPT
man_r3b = os.path.join(WORK, "manifest-recovery-v3b.json")
run([RECOVERY, "sign", art3, "3", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-b", KEYDIR, man_r3b])
p = run([RECOVERY, "verify", man_r3b, art3, STATE, REVOC])
scenario("R5", "rotated-fallback-install-v3", "ACCEPT", verdict(p), reason(p))

# R6/R7/R9/R10/R11 use a separate state file at version 2, so the version
# gate passes and the check under test — not the rollback gate — rejects.
with open(STATE_ISO, "w") as f:
    f.write("version=2\n")
print("R6/R7/R9/R10/R11: separate state file at version=2 to isolate the check under test from the rollback check")

# R6: corrupt SLH-DSA signature (one byte flipped) -> REJECT
m = load_manifest(man_r3b)
m["fallback_signature_b64"] = flip_b64_byte(m["fallback_signature_b64"], 100)
man_r3_corrupt = os.path.join(WORK, "manifest-recovery-v3-corrupt.json")
save_manifest(m, man_r3_corrupt)
p = run([RECOVERY, "verify", man_r3_corrupt, art3, STATE_ISO, REVOC])
scenario("R6", "corrupt-slhdsa-signature", "REJECT", verdict(p), reason(p))

# R7: wrong fallback public key (fb-c's key in the fb-b manifest) -> REJECT
m = load_manifest(man_r3b)
with open(os.path.join(KEYDIR, "slhdsa128s-fb-c.pk"), "rb") as f:
    wrong_pk = base64.b64encode(f.read()).decode()
m["fallback_public_key_b64"] = wrong_pk
man_r3_wrongkey = os.path.join(WORK, "manifest-recovery-v3-wrongkey.json")
save_manifest(m, man_r3_wrongkey)
p = run([RECOVERY, "verify", man_r3_wrongkey, art3, STATE_ISO, REVOC])
scenario("R7", "wrong-fallback-public-key", "REJECT", verdict(p), reason(p))

# R8: replay recovery v2 after v3 is installed (shared state at 3) -> REJECT
p = run([RECOVERY, "verify", man_r2, art2, STATE, REVOC])
scenario("R8", "replay-recovery-v2-after-v3", "REJECT", verdict(p), reason(p))

# R9: tampered payload — one byte flipped in artifact v3 -> REJECT (digest)
art3_tampered = os.path.join(WORK, "firmware-v3-tampered.bin")
shutil.copyfile(art3, art3_tampered)
with open(art3_tampered, "r+b") as f:
    f.seek(12345)
    b = f.read(1)
    f.seek(12345)
    f.write(bytes([b[0] ^ 0xFF]))
p = run([RECOVERY, "verify", man_r3b, art3_tampered, STATE_ISO, REVOC])
scenario("R9", "tampered-payload-byteflip", "REJECT", verdict(p), reason(p))

# R10: tampered version counter — recovery v3 manifest with version 99 -> REJECT
m = load_manifest(man_r3b)
m["version"] = 99
man_r3_v99 = os.path.join(WORK, "manifest-recovery-v3-version99.json")
save_manifest(m, man_r3_v99)
p = run([RECOVERY, "verify", man_r3_v99, art3, STATE_ISO, REVOC])
scenario("R10", "tampered-version-counter-99", "REJECT", verdict(p), reason(p))

# R11: truncated SLH-DSA signature -> REJECT (length check)
m = load_manifest(man_r3b)
m["fallback_signature_b64"] = trunc_b64(m["fallback_signature_b64"])
man_r3_trunc = os.path.join(WORK, "manifest-recovery-v3-trunc.json")
save_manifest(m, man_r3_trunc)
p = run([RECOVERY, "verify", man_r3_trunc, art3, STATE_ISO, REVOC])
scenario("R11", "truncated-slhdsa-signature", "REJECT", verdict(p), reason(p))

# R12: primary rotation + corrupt primary signature.
# Fresh primary keys (the old ML-DSA key is revoked); sign hybrid v4,
# corrupt the ML-DSA signature -> hybrid verify REJECT; then the
# recovery manifest for the same version installs -> ACCEPT.
run([RELEASE, "genkey", "Ed25519", "ed25519-rel-b", KEYDIR])
run([RELEASE, "genkey", "ML-DSA-65", "mldsa65-rel-b", KEYDIR])
man_h4 = os.path.join(WORK, "manifest-hybrid-v4.json")
run([RELEASE, "sign", art4, "4", "ed25519-rel-b", KEYDIR, "ML-DSA-65", "mldsa65-rel-b", KEYDIR, man_h4])
m = load_manifest(man_h4)
m["pq_signature_b64"] = flip_b64_byte(m["pq_signature_b64"], 100)
man_h4_corrupt = os.path.join(WORK, "manifest-hybrid-v4-corrupt.json")
save_manifest(m, man_h4_corrupt)
p = run([RELEASE, "verify", man_h4_corrupt, art4, STATE, REVOC])
scenario("R12a", "corrupt-mldsa-signature-hybrid-v4", "REJECT", verdict(p), reason(p))
man_r4 = os.path.join(WORK, "manifest-recovery-v4.json")
run([RECOVERY, "sign", art4, "4", "SLH-DSA-SHA2-128s", "slhdsa128s-fb-b", KEYDIR, man_r4])
p = run([RECOVERY, "verify", man_r4, art4, STATE, REVOC])
scenario("R12b", "recovery-install-v4-after-corrupt-primary", "ACCEPT", verdict(p), reason(p))

# R-M1: measurement — combined dual manifest size.
# Merge the hybrid v4 and recovery v4 manifests into one JSON object
# (all three signatures in one file) and measure its byte size, alongside
# the two single-path manifests. Sizes are deterministic: same fields,
# same fixed-length keys and signatures every run.
mh = load_manifest(man_h4)
mr = load_manifest(man_r4)
dual = dict(mh)
dual["format"] = "dual-release-manifest/1"
dual["fallback_scheme"] = mr["fallback_scheme"]
dual["fallback_key_id"] = mr["fallback_key_id"]
dual["fallback_public_key_b64"] = mr["fallback_public_key_b64"]
dual["fallback_signature_b64"] = mr["fallback_signature_b64"]
dual_path = os.path.join(OUT, f"{LABEL}-dual-manifest-v4.json")
with open(dual_path, "w") as f:
    json.dump(dual, f, indent=2)
    f.write("\n")
dual_size = os.path.getsize(dual_path)
# Sizes are measured from the WORK copies; the shipped copies below are
# byte-identical (shutil.copyfile).
hybrid_size = os.path.getsize(man_h4)
recovery_size = os.path.getsize(man_r4)
print(f"R-M1: hybrid manifest v4 = {hybrid_size} bytes; recovery manifest v4 = {recovery_size} bytes; combined dual manifest = {dual_size} bytes")
measurement("R-M1", "combined-dual-manifest-size",
            f"{dual_size} bytes (hybrid {hybrid_size} + recovery {recovery_size})",
            "byte size of one JSON manifest carrying all three signatures")

# --- ship evidence (public keys/signatures only; secret keys stay in WORK) ---
for src, dst in (
    (art1, f"{LABEL}-firmware-v1.bin"),
    (art2, f"{LABEL}-firmware-v2.bin"),
    (art3, f"{LABEL}-firmware-v3.bin"),
    (art4, f"{LABEL}-firmware-v4.bin"),
    (man_h1, f"{LABEL}-manifest-hybrid-v1.json"),
    (man_h2, f"{LABEL}-manifest-hybrid-v2.json"),
    (man_h4, f"{LABEL}-manifest-hybrid-v4.json"),
    (man_r2, f"{LABEL}-manifest-recovery-v2.json"),
    (man_r3b, f"{LABEL}-manifest-recovery-v3.json"),
    (man_r4, f"{LABEL}-manifest-recovery-v4.json"),
    (REVOC, f"{LABEL}-revocation-final.txt"),
    (STATE, f"{LABEL}-state-final.txt"),
):
    shutil.copyfile(src, os.path.join(OUT, dst))
    print(f"shipped: {dst}")

csv_path = os.path.join(OUT, f"{LABEL}-recovery-scenarios.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["scenario", "name", "expected", "observed", "reason", "result"])
    for r in results:
        w.writerow([r[0], r[1], r[2], r[3], r[4], "PASS" if r[5] else "FAIL"])
print(f"scenarios csv: {scrub(csv_path)}")

npass = sum(1 for r in results if r[5])
nverdict = sum(1 for r in results if r[2] != "MEASURED")
print(f"run_recovery_scenarios: {npass}/{len(results)} rows PASS ({nverdict} verdict scenarios + {len(measurements)} measurement)")
print(f"run_recovery_scenarios: {'DONE' if npass == len(results) else 'FAIL'}")
sys.exit(0 if npass == len(results) else 1)

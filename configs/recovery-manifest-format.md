# Recovery manifest format — `recovery-release-manifest/1`

A recovery manifest is a flat JSON object (one level, unique keys)
describing one release artifact signed with the SLH-DSA fallback key.
It is the recovery path for a release whose primary hybrid signature
(Ed25519 + ML-DSA, see `configs/manifest-format.md`) can no longer be
used — the ML-DSA key was compromised and revoked, or the primary
signature itself is corrupt. The recovery manifest stands alone: it
carries only the fallback signature, over the same artifact and the
same version number as the hybrid release it recovers.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `format` | string | Always `"recovery-release-manifest/1"`. |
| `artifact` | string | File name of the release artifact (base name only). |
| `artifact_sha256` | string | Lowercase hex SHA-256 of the artifact bytes. |
| `artifact_size` | integer | Artifact size in bytes. |
| `version` | integer | Monotonic release version (unsigned 64-bit). Must be strictly greater than the installed version recorded in the verifier state file. Same version space as the hybrid manifests — a recovery install advances the same counter. |
| `fallback_scheme` | string | SLH-DSA scheme, one of the twelve FIPS 205 pure sets, e.g. `"SLH-DSA-SHA2-128s"`. |
| `fallback_key_id` | string | Identifier of the SLH-DSA fallback signing key. |
| `fallback_public_key_b64` | string | Base64 of the SLH-DSA public key (32 / 48 / 64 bytes, FIPS 205 Table 2). |
| `fallback_signature_b64` | string | Base64 of the SLH-DSA signature over the TBS bytes (7,856–49,856 bytes, FIPS 205 Table 2). |

## To-be-signed (TBS) bytes

The fallback signature is computed over the TBS string, built from the
manifest fields (not from the JSON text, so key order and whitespace in
the file do not matter):

```
recovery-release-manifest/1\n
<artifact_sha256>\n
<version as decimal>\n
<artifact_size as decimal>\n
<fallback_key_id>\n
<fallback_scheme>\n
```

Changing any covered field (digest, version, size, key id, scheme name)
invalidates the fallback signature. The `format` line pins the TBS
layout to this manifest version.

The TBS does NOT include the primary (hybrid) key ids or signatures:
the recovery manifest is not cryptographically bound to a specific
hybrid manifest. The linkage is operational — same artifact bytes, same
version number — and is demonstrated by the scenario suite
(`scripts/run_recovery_scenarios.py`, scenarios R2–R3, R12). Binding the
recovery signature to the hybrid manifest's digest is a possible
hardening, listed as a design note in `docs/methodology.md`.

## Verification order (`recovery verify`)

1. Artifact digest and size must match the manifest (tampered payload rejected).
2. Manifest `version` must be strictly greater than the installed version
   in the state file (rollback rejected). The state file is the SAME file
   the primary harness uses, so a recovery install advances the same
   monotonic counter and a later hybrid install must use a higher version.
3. The fallback key id must not appear in the revocation list (compromised
   fallback key rejected). The revocation list is the SAME file the primary
   harness uses; fallback key ids share its namespace.
4. Decoded public-key and signature lengths must equal the expected lengths
   for the named scheme (FIPS 205 Table 2, via the pinned liboqs lengths).
5. The fallback signature is verified against the recomputed TBS.
6. On ACCEPT the state file is updated to the manifest version.

## Example

See `outputs/run1-manifest-recovery-v2.json` (signed artifact
`run1-firmware-v2.bin`, the same artifact and version as the hybrid
release `outputs/run1-manifest-hybrid-v2.json` whose ML-DSA key was
revoked).

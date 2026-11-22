# Release manifest format — `hybrid-release-manifest/1`

A release manifest is a flat JSON object (one level, unique keys) describing
one signed release artifact. Both signatures cover the same canonical
to-be-signed (TBS) bytes, so each signature can be verified independently
of the other.

## Fields

| Field | Type | Meaning |
|---|---|---|
| `format` | string | Always `"hybrid-release-manifest/1"`. |
| `artifact` | string | File name of the release artifact (base name only). |
| `artifact_sha256` | string | Lowercase hex SHA-256 of the artifact bytes. |
| `artifact_size` | integer | Artifact size in bytes. |
| `version` | integer | Monotonic release version (unsigned 64-bit). Must be strictly greater than the installed version recorded in the verifier state file. |
| `classical_scheme` | string | Classical scheme, `"Ed25519"`. |
| `classical_key_id` | string | Identifier of the classical signing key. |
| `classical_public_key_b64` | string | Base64 of the 32-byte Ed25519 public key (RFC 8032). |
| `classical_signature_b64` | string | Base64 of the 64-byte Ed25519 signature over the TBS bytes. |
| `pq_scheme` | string | Post-quantum scheme, one of `"ML-DSA-44"`, `"ML-DSA-65"`, `"ML-DSA-87"`. |
| `pq_key_id` | string | Identifier of the ML-DSA signing key. |
| `pq_public_key_b64` | string | Base64 of the ML-DSA public key (1312 / 1952 / 2592 bytes, FIPS 204 Table 2). |
| `pq_signature_b64` | string | Base64 of the ML-DSA signature over the TBS bytes (2420 / 3309 / 4627 bytes, FIPS 204 Table 2). |

## To-be-signed (TBS) bytes

Both signatures are computed over the same TBS string, built from the
manifest fields (not from the JSON text, so key order and whitespace in
the file do not matter):

```
hybrid-release-manifest/1\n
<artifact_sha256>\n
<version as decimal>\n
<artifact_size as decimal>\n
<classical_key_id>\n
<pq_key_id>\n
<classical_scheme>\n
<pq_scheme>\n
```

Changing any covered field (digest, version, size, key ids, scheme names)
invalidates both signatures. The `format` line pins the TBS layout to
this manifest version.

## Verification order (`release verify`)

1. Artifact digest and size must match the manifest (tampered payload rejected).
2. Manifest `version` must be strictly greater than the installed version
   in the state file (rollback rejected).
3. Neither key id may appear in the revocation list (compromised key rejected).
4. Decoded public-key and signature lengths must equal the expected lengths
   for the named scheme (FIPS 204 §3.6.2 length checks; Ed25519 32/64 per
   RFC 8032 §1).
5. Each signature is verified independently against the recomputed TBS;
   both must be valid.
6. On ACCEPT the state file is updated to the manifest version.

## Example

See `outputs/run1-manifest-v2.json` (signed artifact `run1-firmware-v2.bin`).

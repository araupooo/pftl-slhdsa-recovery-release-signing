# Revocation-list format

A revocation list is a plain-text file, one compromised key id per line.

- Lines starting with `#` are comments and are ignored.
- Blank lines and surrounding whitespace are ignored.
- Every other line is a key id, matched exactly (case-sensitive) against
  the `classical_key_id` and `pq_key_id` fields of a manifest.

## Behaviour

`release verify` rejects a manifest when either of its key ids appears
in the revocation list, before any signature is checked (see
`configs/manifest-format.md` for the check order). The rejection reason
names the revoked key id.

## Example

```
# revocation list: one key id per line
mldsa65-rel-a
```

A key id stays on the list permanently: rotation issues a new key id
rather than removing the old one, so artifacts signed by the compromised
key keep being rejected after rotation (scenario S10 in the logs).

## Key rotation

1. Generate a new key pair under a new key id (`release genkey`).
2. Add the compromised key id to the revocation list.
3. Sign the next release version with the new key id.
4. Verify the new release: it must ACCEPT, and the old release must
   still REJECT.

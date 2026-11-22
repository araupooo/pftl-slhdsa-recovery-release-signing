# Monotonic version-counter policy

## Rule

Release versions are unsigned 64-bit integers, assigned in strictly
increasing order (1, 2, 3, ...). A verifier keeps one piece of state:
the highest version it has accepted (`version=<n>` in the state file,
initially absent = 0).

A manifest is accepted only if its `version` is **strictly greater**
than the stored installed version. Equal or lower versions are rejected
as rollback attempts. On ACCEPT the stored version is updated to the
manifest version.

## Consequences

- Re-installing the same version is rejected (no downgrade, no replay
  of an already-installed release).
- A manifest whose `version` field was edited after signing is rejected
  even if the edited number is higher: the version is covered by both
  signatures (see `configs/manifest-format.md`), so the edit invalidates
  them (scenario S3).
- Version numbers are never reused, and a new key rotation does not
  reset the counter: the first release under rotated keys takes the
  next version number (scenario S9 signs version 3 after version 2).

## State file

Plain text, one line:

```
version=2
```

The state file is local verifier state, not part of the signed release.
A verifier that loses its state file (installed version resets to 0)
would accept an older signed release again; protecting the state file
against deletion or rollback is a deployment requirement, not something
this harness can enforce. That is recorded as limitation L5 in
`docs/methodology.md`.

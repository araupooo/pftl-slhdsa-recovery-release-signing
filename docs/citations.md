# Citations

Primary sources only. Every spec claim in this pack traces to one of
these; measured claims trace to the logs listed in
`docs/claim-evidence-index.md`. No secondary sources (blogs, vendor
pages, summaries) are cited for any claim in this pack.

## SLH-DSA

- **FIPS 205 — Stateless Hash-Based Digital Signature Standard**
  (NIST, 13 Aug 2024). https://csrc.nist.gov/pubs/fips/205/final
  (DOI: https://doi.org/10.6028/NIST.FIPS.205)
  - §11, Table 2: sizes in bytes — SLH-DSA-128s: private key 64,
    public key 32, signature 7,856; 128f: 64 / 32 / 17,088; 192s:
    96 / 48 / 16,224; 192f: 96 / 48 / 35,664; 256s: 128 / 64 / 29,792;
    256f: 128 / 64 / 49,856. SHA2 and SHAKE variants of a tuple have
    identical sizes. Security strength categories 1 / 3 / 5.
    Verified against the liboqs implementation in
    `outputs/bench-slhdsa-run*.log` (see `docs/claim-evidence-index.md`
    C1).
  - §3.1: private key = 4n bytes, public key = 2n bytes; each key
    supports up to 2^64 signatures.
  - §11: the `s`/`f` choice trades signature size against signing
    speed only; it does not change the security category.

## ML-DSA

- **FIPS 204 — Module-Lattice-Based Digital Signature Standard**
  (NIST, 13 Aug 2024). https://csrc.nist.gov/pubs/fips/204/final
  (DOI: https://doi.org/10.6028/NIST.FIPS.204)
  - §4, Table 2: sizes in bytes — ML-DSA-44: private key 2560,
    public key 1312, signature 2420; ML-DSA-65: 4032 / 1952 / 3309;
    ML-DSA-87: 4896 / 2592 / 4627. Security strength categories 2 / 3 / 5.
    The 2560 / 4032 / 4896 private-key figures are the expanded-form
    figures; some secondary write-ups list 2528 / 4000 / 4864 (32 bytes
    less, apparently omitting one 32-byte component). This pack uses
    the FIPS 204 Table 2 figures and confirms them against the liboqs
    implementation in `outputs/bench-sig-run*.log`.
  - §3.6.2 (public-key and signature length checks): the basis for the
    length gate in `release verify`.
  - §5.2 (ML-DSA.Sign): signing takes a private key, a message, and a
    context string; the default hedged variant generates a 32-byte
    random value. The harness signs the TBS bytes with the default
    variant and an empty context.
  - §5.4 (pre-hash ML-DSA): "In general, the 'pure' ML-DSA version is
    preferred." The harness therefore signs the TBS directly rather
    than using HashML-DSA; the artifact digest is part of the TBS.
  - §5.3 (ML-DSA.Verify): verification outputs a Boolean, true only
    if the signature is valid for the message and public key.

## Classical signatures

- **RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)**
  (Josefsson & Liusvaara, IRTF, Jan 2017).
  https://datatracker.ietf.org/doc/html/rfc8032
  - §1: "EdDSA uses small public keys (32 or 57 bytes) and signatures
    (64 or 114 bytes) for Ed25519 and Ed448, respectively"; Ed25519 is
    intended for around the 128-bit security level; "A sufficiently
    large quantum computer would be able to break both."
    Verified against the OpenSSL EVP implementation in
    `outputs/bench-sig-run*.log`.

## Composite signatures

- **RFC 10073 — Composite Module-Lattice-Based Digital Signature
  Algorithm (ML-DSA)** (IETF LAMPS). https://www.rfc-editor.org/rfc/rfc10073.txt
  - Composite ML-DSA combines ML-DSA with a classical scheme
    (RSASSA-PKCS1-v1.5, RSASSA-PSS, ECDSA, Ed25519, or Ed448) into a
    single atomic algorithm. Verified live 22 Nov 2026: the RFC text
    was fetched and read during this pack's build.
  - §8.2: `id-MLDSA65-Ed25519-SHA512`, OID 1.3.6.1.5.5.7.6.48.
  - §9.2: composite ML-DSA provides EUF-CMA, not SUF-CMA; "applications
    where it has not been shown that EUF-CMA is acceptable" should not
    use it.
  - No SLH-DSA composite is defined in RFC 10073. The ML-DSA +
    SLH-DSA construction in this pack is therefore dual (non-composite)
    signing with an AND verification policy, not a standardised
    composite; see `docs/methodology.md` D3.

## Firmware signing practice

- **NIST SP 800-193 — Platform Firmware Resiliency Guidelines**
  (NIST, May 2018). https://csrc.nist.gov/pubs/sp/800/193/final
  - Protection, Detection, Recovery, with a Root of Trust for Update
    (RTU), Detection (RTD) and Recovery (RTRec); the RTD validates
    firmware by signature or hash before execution.
- **RFC 9019 — A Firmware Update Architecture for Internet of Things
  Devices** (IETF SUIT, Apr 2021) and **RFC 9124 — A Manifest
  Information Model for Firmware Updates** (IETF SUIT, Jan 2022).
  https://datatracker.ietf.org/doc/html/rfc9019,
  https://datatracker.ietf.org/doc/html/rfc9124
  - Required manifest elements include a monotonic sequence number,
    payload digests, payload size and (for standalone manifests) a
    signature.
- **The Update Framework (TUF), specification v1.0.36** (CNCF,
  Aug 2026). https://theupdateframework.io/specification/latest/
  - Four roles (Root, Targets, Snapshot, Timestamp) with thresholds;
    chained root rotation; fast-forward recovery after key rotation.
- **NIST SP 800-208 — Recommendation for Stateful Hash-Based
  Signature Schemes** (NIST, Oct 2020).
  https://csrc.nist.gov/pubs/sp/800/208/final
  - LMS/XMSS for software and firmware signing (the CNSA 2.0 choice);
    state management requirements for one-time keys.

## Migration guidance and policy

- **NIST CSRC — Post-Quantum Cryptography project page.**
  https://csrc.nist.gov/projects/post-quantum-cryptography
  - "NIST released the principal three PQC standards in 2024";
    "Organizations should begin applying these standards now to
    migrate their systems to quantum-resistant cryptography."
- **NIST IR 8547 — Transition to Post-Quantum Cryptography Standards**
  (NIST, final Oct 2026). https://csrc.nist.gov/pubs/ir/8547/final
  - Quantum-vulnerable algorithms deprecated and ultimately removed
    from NIST standards by 2035, "with high-risk systems transitioning
    much earlier."
- **CNSA 2.0 (NSA, via CNSSP 15; NSA CNSA 2.0 FAQ v2.2, Oct 2026).**
  - ML-DSA-87 for general signatures; LMS/XMSS (SP 800-208) for
    software and firmware signing; required in new NSS acquisitions
    from 1 Jan 2027; mandated for use by 31 Dec 2031.

## Attack surface (cited, not re-derived)

- **Zhou et al., TCHES 2025(4), pp. 817–847**
  (DOI: https://doi.org/10.46586/tches.v2025.i4.817-847).
  - Rejected-signature challenges leak through power/EM; converting
    the leakage to an integer linear program recovers the Dilithium
    private key in seconds or minutes with 100% success rate at all
    three security levels, demonstrated with real power traces on ARM
    Cortex-M4.
- **Zhao et al., ePrint 2026/056 ("Rejection Matters").**
  https://eprint.iacr.org/2026/056
  - Public-template attack using leakage from both rejected and
    accepted signing trials, needing no clone device; challenges fully
    recovered with 96 power traces and key recovery in ~300 traces for
    ML-DSA-44.

## Implementations

- **liboqs 0.16.0** — https://github.com/open-quantum-safe/liboqs —
  the library implementing ML-DSA and SLH-DSA. Tag commit
  `5a1a854b0dc9f2141bdc771c555ee60c37950183`, released 9 Jul 2026.
  Version string printed in `outputs/bench-*-run*.log`
  (`liboqs version: 0.16.0`). The SLH-DSA parameter table in the
  pinned source tree (`src/sig/slh_dsa/sig_slh_dsa.h`) matches FIPS 205
  Table 2 exactly, and the ML-DSA table
  (`docs/algorithms/sig/ml_dsa.md`) matches FIPS 204 Table 2.
  The liboqs README states the project does not currently recommend
  relying on liboqs in production or to protect sensitive data; this
  pack is explicitly non-production.
- **OpenSSL 3.0.13** — https://www.openssl.org/ — the EVP API used
  for Ed25519 key generation, signing, and verification, and for
  SHA-256 artifact digests. Version string printed in the bench logs.

## Prior packs (cross-check sources, not spec sources)

- **Hybrid release-signing evidence pack (live repo)** —
  https://github.com/araupooo/pftl-hybrid-release-signing-evidence-pack —
  HEAD `2a141f4e397ffdabcce15ebbd2557fccc3ace0f7`, pushed 20 Nov 2026.
  Its SLH-DSA timing claims (docs/claims.md M-04–M-07) are the
  cross-stack check targets for this pack's liboqs measurements; see
  `docs/reuse.md`.
- **Hybrid ML-DSA firmware signing pack (local, unpublished)** —
  built 12 Nov 2026, PACK-READY 12 Nov ~22:40 WIB, never published.
  Its harness (`src/release.c`, `src/bench_sig.c`) and configs are
  reused verbatim in this pack; see `docs/reuse.md`.
- **Post-quantum release-signing assessment (liboqs cross-check)** —
  https://github.com/araupooo/postfiat-release-signing-pqc-assessment —
  HEAD `aef7ab057c076dd745e26120f71bc7e598aa2324`. Cited by the live
  repo for liboqs SLH-DSA-128s signing at 692.7 ms; cross-check only.

## Notes on sources

- FIPS 204, FIPS 205, RFC 8032, RFC 10073, and the NIST CSRC PQC page
  were fetched and read during research or build for this pack
  (Nov 2026). RFC 10073 was fetched live on 22 Nov 2026 and the
  id-MLDSA65-Ed25519-SHA512 OID and the EUF-CMA-only statement were
  confirmed in the fetched text.
- No secondary sources (blogs, vendor pages, summaries) are cited for
  any claim in this pack.

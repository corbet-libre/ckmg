# Required cryptographic review

Status: **not independently audited; not production accepted**. Established
primitives do not prove that the composition, custody model or integrations are
secure. Review [CONSTRUCTIONS](CONSTRUCTIONS.md), [CONTRACT](CONTRACT.md) and the
actual public API together. Record findings, exploit/reproduction evidence,
resolutions and the exact reviewed source/dependency revisions.

## Derivation and restoration

- Check the entropy and stability of cpky's PRF output on every supported native,
  browser and synced-provider path. Fix/version its evaluation input outside ckmg;
  reject absent, truncated or substituted results and wipe adapter-owned copies.
- Independently reproduce every HKDF vector, label, NUL delimiter, domain spelling,
  output length, epoch encoding and first-level/epoch salt. Check domain separation
  across wallet, communities, store wrapping, signing, encryption and lineage.
- Check that initial keys, identity root and holder seed survive total checkpoint
  loss with a fresh device and independent RNG. Roots must not depend on random
  nonces, local device names, credential IDs, time or the lost checkpoint.
- Review deterministic rotations: a removed distinct credential gets no lineage
  seed; epoch reuse must be bound to authenticated current lineage and durable CAS.
  The same compromised/synced PRF cannot be selectively revoked as separate hardware.
  No forward secrecy or post-compromise healing is claimed for derived roots.
- Verify Restore authority binds the exact current lineage digest, member binding,
  root, epoch and derived device, not just a self-signature. Try stale revisions,
  revoked credentials, changed pseudonyms, wrong scopes, fake absence, read failures,
  corrupt records, concurrent writers and cancelled/unknown writes. None may create
  a new member, reset obligations or resurrect removed authority.
- Validate retention of pairing/rotation envelopes independently of vault content.
  An unrelated PRF cannot derive another credential's shared root without a transfer.
  If all such transfers disappear, stable personal seeds remain derivable but that
  shared root cannot be reconstructed. Resolve this in the product's retention and
  reenrollment design before promising all-passkey restoration after every loss.

## Passport and membership integration gates

- The holder seed is derived and kept opaque here; there is currently **no adapter
  to the existing cpsd holder engine**. Review and implement the versioned mapping
  into its established nonzero-scalar construction inside custody, with no raw seed,
  scalar or deterministic-RNG export. Do not substitute an Ed25519 key or invent BBS.
- Prove unchanged issuer tag and community pseudonyms across device loss using the
  real passport engine, then renew/reissue lost credential data through existing
  issuer rules. This library does not recreate signatures an issuer never issued.
- Test live ckyh/cpky/cvlt authority, discoverable sign-in and current revocation,
  including fresh authorized restoration with empty data and unchanged cblc state.
  The native/Wasm fixture Authority is not production authorization evidence.
- Run the cdht churn/device-loss scenario: an active member's contacts and history
  return when encrypted records survive; only data is lost when records are gone.
  Key tests do not establish DHT retention or product restoration by themselves.

## Cryptographic compositions

- Compare VLD0 Ed25519ph context, prehash, strict verification, weak/noncanonical
  points, typed encoding and hashes with Veilid. Confirm plain Ed25519 cannot be
  confused with VLD0 and owner transcripts bind all their required claims.
- Review Ed25519-to-X25519 conversion, HPKE suite/info/header, weak/all-zero DH
  handling and upstream error behavior. Base mode requires external authentication:
  verify grant/rotation signatures, recipient, request digest, lineage digest and
  authenticated current authority before accepting any recovered root.
- Review AEAD nonce uniqueness across processes, restored devices, same-PRF clients
  and failed transactions; nonce/HPKE randomness remains fresh. Check all AAD and
  header bindings, truncation/tampering, input limits and plaintext-on-error handling.
- Review BLAKE3 purpose derivation, parent independence, signing/encryption domains,
  generation/epoch boundaries and member/device scope. Revoked signatures must be
  rejected by consumers using current lineage, not merely cryptographically verified.
- Check canonical transcript stability across native and Wasm, serialization bounds,
  unknown fields, malformed keys and counter overflows. Transport adapters must
  bound input before allocation. Public identifiers and locators must not leak via
  logs, traces or error strings.

## Custody, authority and persistence

- Audit every public surface for raw key getters, serde/Debug/Clone exposure,
  plaintext roots, opaque-handle bypasses and identity correlation. `StoreCipher`
  is a wrapping capability only and must not decrypt custody checkpoints.
- Inspect zeroization of HKDF intermediates and upstream hash/HMAC/HPKE/RNG state,
  dalek seeds, serialized plaintext, transient copies, drops and async cancellation.
  Inspect browser JS/Wasm copies and process-memory isolation separately; no promise
  of erasing registers, snapshots, swap or hostile same-process reads is implied.
- Exercise the real SecureStore's durability, atomic CAS, no-ABA/rollback guarantee,
  authoritative absence, bounded reads and composite output publication. Verify
  receipts survive crash-after-commit and are published/acknowledged idempotently.
- Race pairing consent, expiration, rotation approval, authority changes and storage
  commits. Define how production adapters close freshness/TOCTOU gaps; per-operation
  checks alone are not a cross-service transaction. Verify rotation cannot publish
  both competing successors or revive revoked keys after checkpoint loss.
- Check dependency features, advisories, licenses and resolved revisions on both
  targets. Keep Veilid-derived MPL material isolated. Reference tests using the same
  upstream primitives are interoperability evidence, not independent crypto review.

## Boundary regression checks

No `passkey::browser`, WebAuthn request/assertion types, credentials APIs or PRF
salt generation may return to Keys. cpky alone talks to the authenticator; ckyh
verifies server authentication and rejects PRF-bearing responses. cwst receives
only an opaque wrapping handle. Neither a policy engine, an operator recovery
credential nor a new enrollment shortcut belongs in this library.

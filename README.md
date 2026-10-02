# ckmg — Keys

Keys is the cryptographic custody library of the member vault (`cvlt`). It derives
stable secrets from an opaque passkey PRF input, holds root/device/purpose keys,
signs and seals, pairs devices, and commits root rotations atomically. Native and
wasm32 use the same Rust implementation and crypto tests.

The **passkey is the key**. Device-side **cpky Passkeys** is the only library that
talks to WebAuthn. Server-side **ckyh Keyhole** stores the public credential and
verifies authentication. Keys never constructs WebAuthn options or handles RP IDs,
challenges, assertions or credential responses. See the [adapter move](docs/PASSKEYS.md).

## Custody and restoration

`passkey::PrfOutput::from_bytes` accepts exactly 32 bytes from a trusted local
adapter. It has no byte getter, Debug implementation or serialization. Independent
HKDF domains derive the vault locator, custody key, opaque `StoreCipher`, identity
root, passport holder secret seed, device seed and member-lineage seed. Root epochs
are derived from the credential-local lineage seed. Nonces, pairing challenges,
session IDs and operation IDs still require secure randomness.

`Keys<S, C, R, A>` receives storage, clock, entropy and current-authority ports.
`create_scope` requires explicit registration authority. `unlock` opens an existing
checkpoint. If storage authoritatively reports absence, `restore_scope` can rebuild
the same keys against authenticated current lineage, without changing the member
binding. An unreachable store is an error, never permission to create an identity.

The same synced passkey represents the same logical device. Rebuilding its initial
custody needs no old vault ciphertext. A separate passkey paired into a shared root,
or a survivor of another credential's rotation, needs its retained authenticated
root envelope. The vault integration must retain those transfers with authority
metadata independently of disposable content. See [restoration boundaries](docs/CONTRACT.md#restoration-boundaries).

`passkey::identity_roots` independently restores stable wallet identity custody and
the passport holder seed without records. The seed remains internal: connecting it
to the existing passport engine without an export API is a downstream integration
gate, not an implemented credential issuance or membership-renewal flow. Lost
contacts/history cannot be recreated from keys; available encrypted data remains
readable with the same keys.

## Cryptographic operations

- Opaque `KeyHandle` capabilities bind purpose, community/member, device and epoch.
  Operations recheck current authority; locking and rotation invalidate old handles.
- VLD0 uses typed `VLD0:<base64url-no-pad>` keys, Ed25519ph with `VLD0_SIGN`,
  Veilid-compatible HPKE and BLAKE3. Plain Ed25519 has a separate API.
- XChaCha20-Poly1305 protects custody, purpose data and storage wrapping. `cwst`
  receives only `StoreCipher`, never a PRF or raw wrapping key.
- Pairing and rotation expose signed public metadata and recipient-bound encrypted
  roots only. No secret getter, plaintext key serialization, operator recovery,
  backup service, network or filesystem implementation is included.

Every construction and domain label is specified in [CONSTRUCTIONS](docs/CONSTRUCTIONS.md).
The [contract](docs/CONTRACT.md) covers authority and crash behavior.
[SECURITY-REVIEW](docs/SECURITY-REVIEW.md) lists the independent review and integration
checks required before production use. Test vectors are evidence, not an audit.

## Validation

GitHub Actions runs formatting, native Clippy/tests, wasm32 Clippy, and the shared
crypto/state suite in headless Chrome. Dependencies are recorded in `Cargo.lock`.
No local workstation builds are required. Veilid reference tests remain isolated
under MPL-2.0; production depends on upstream crypto crates, never `veilid-core`.

## Scope

### Purpose

ckmg is the member's key ring inside the member vault: it holds root, device, and purpose keys, signs and seals, pairs devices, and derives vault location and storage keys from an opaque passkey PRF input without ever seeing WebAuthn.

### Owns

- Community-local root, device, and purpose key custody, lending purpose keys narrowly to Veilid, OpenMLS, and Arti.
- Deterministic derivation of root secrets, vault locator, and storage wrapping capability from the PRF input.
- Signed device lineage: pairing from a live device only with the root sealed to the new device, and removal with a new epoch and key rotation.
- Private device names and authority references.
- Typed VLD0 keys and signatures.
- Separate holder custody in the wallet scope.

### Never

- Touches WebAuthn, including options, challenges, credential identifiers, or assertions.
- Exports root or holder secrets, or shares keys or locators across communities.
- Treats an unsigned public key as authorization, or uses a globally stable root as a member identifier.
- Provides operator recovery, backup service, or plaintext export.
- Performs network or filesystem I/O, depends on veilid-core, or builds its own cryptographic primitives.
- Emits identifiers, plaintext, or secrets in errors, or sends personal identifiers in outbound requests.

### States

Locked, Authorized, PendingDevice, and MissingCheckpoint for device custody; Prepared to committed for writes; Prepared to Authorized for rotation; Revoked after removal; Reconcile after an uncertain write; and Unrecoverable when no passkey or record survives, which never creates a new identity.

### Test obligations

- Signatures bind purpose, community, member, device, and epoch; wrong-purpose and revoked handles fail.
- The same person in two communities gets independent keys, and the same PRF input regenerates the same roots without a vault record.
- Absent records are distinguished from unreachable stores; an unreachable store never authorizes creating a new identity.
- Rotation preserves the existing membership identity and its obligations; a crash before or after the rotation commit never authorizes old and new state together.
- Pairing, clock regression, tampering, corruption, and cancellation are covered on native and WebAssembly with identical test vectors.
- Full line and branch coverage with real round trips and no mocks of its own logic, including injected delay, duplication, loss, cancellation, clock regression, corruption, and storage conflicts.
- Atomic publication with durable acceptance and reconciliation of unknown outcomes without regenerating keys, proofs, or effects, keeping each community isolated and all inputs bounded.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

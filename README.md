# ckmg — Keys

Keys is the cryptographic custody library of the member vault (`cvlt`). It derives
wrapping and device secrets from opaque passkey PRF input, holds random common roots,
signs and seals, pairs devices, and commits root rotations atomically. Native and
wasm32 use the same Rust implementation and crypto tests.

The **passkey is the key**. Device-side **cpky Passkeys** is the only library that
talks to WebAuthn. Server-side **ckyh Keyhole** stores the public credential and
verifies authentication. Keys never constructs WebAuthn options or handles RP IDs,
challenges, assertions or credential responses. See the [adapter move](docs/PASSKEYS.md).

## Scope

Keys owns private root, device and purpose custody, signed device lineage and
narrow signing/sealing capabilities. It lives under Vault and receives storage,
clock, entropy and current authority from that composition. It never performs
WebAuthn, membership decisions, network discovery or operator recovery. Wallet owns
passport state and presentations; Keys supplies its private purpose-separated seed.

Every enrolled passkey has equal recovery implications. A common identity root is
random. Each passkey protects its own encrypted copy in member-owned records;
no first passkey can reconstruct identity after all retained copies disappear.

## Custody and restoration

`passkey::PrfOutput::from_bytes` accepts exactly 32 bytes from a trusted local
adapter. It has no byte getter, Debug implementation or serialization. Independent
HKDF domains derive the vault locator, custody key, opaque `StoreCipher` and logical
device seed. Common identity roots and replacement epoch roots use fresh CSPRNG
entropy. Holder and identity-purpose seeds derive from the retained common root.

`create_scope` requires explicit new-member authority and commits a random root.
`unlock` opens a retained encrypted checkpoint. `restore_scope` requires current
membership authority and an authenticated retained transfer. Historical `Derived`
requests refuse recordless recovery. An unreachable store is an error, never
permission to create an identity or declare permanent loss.

Paired passkeys retain the same common root under separate PRF-based custody keys.
Rotation excludes the removed device from new epoch envelopes while preserving the
common identity and accounting binding. Wrapped copies belong in the member's DHT
records and are refreshed during use. There is no operator copy. Loss of all local
and DHT copies loses identity and data equally for every passkey.

Optional `passport` support delegates to Wallet's `PassportHolder` and borrowed
`PassportSession` after fresh Keys authorization. Keys copies no passport operations
and exposes no engine or seed. Durable passport checkpoint and real network restore
integration remain acceptance obligations; this leaf alone proves no DHT retention.

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

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

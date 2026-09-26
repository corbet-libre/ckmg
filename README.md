# ckmg

**Keys of the member vault: root → device → purpose, in Veilid's VLD0 format.**

`ckmg` is the key drawer of the vault (`cvlt`). It holds the member root and the device
key, derives purpose keys, signs, verifies, seals and opens, and turns the passkey PRF
into the secrets that unlock the vault. It uses the crypto crates Veilid uses
(ed25519-dalek, hpke with X25519 and ChaCha20-Poly1305, chacha20poly1305, blake3) and
Veilid's VLD0 semantics and typed-key format, but not `veilid-core` (one Veilid stack
only).

## Hierarchy

| Key | Where it lives | Leaves the vault? |
|---|---|---|
| Member root | every device of the member | only sealed to a new device during pairing, from a live device |
| Device key | one device | never |
| Purpose key (member scope) | derived from the root | yes, delegated narrowly (e.g. a record writer, the member's record encryption key) |
| Purpose key (device scope) | derived from the device key | yes, delegated narrowly (e.g. OpenMLS signature key, onion service key) |

Purpose keys derive one-way (BLAKE3 key derivation over parent, label and version), so a
delegated key never exposes its parent and compromising it affects only its purpose.
Rotation = next version. A [`Delegation`](src/purpose.rs) is the parent's signed statement
that a public key serves a purpose until a given time.

## Formats (Veilid VLD0)

- Typed keys: `VLD0:<base64url>` as text, `VLD0 ‖ bytes` as binary.
- Signatures: Ed25519ph with context `VLD0_SIGN` (tested against a direct
  ed25519-dalek signature), so purpose keys can own and write Veilid DHT records.
- Sealing to a key: HPKE (RFC 9180) DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
  ChaCha20-Poly1305, with Veilid's Ed25519 → X25519 conversion.
- `verify_ed25519`: plain Ed25519 for statements others sign without VLD0 (e.g. `cvld`
  admission grants).
- Migration hook: `KeyRing::migrate`; only VLD0 exists, so it accepts only VLD0 for now.

## Passkeys

`passkey` (window context only; WebAuthn is unavailable in workers, hence the vault
iframe):

- `browser::register`: create a discoverable, user-verified passkey with the PRF extension;
  returns the registration for `cpky` (server) to verify.
- `browser::login`: sign a login challenge from `cvld` (WebAuthn assertion) and evaluate
  the PRF; `browser::unlock` requires the PRF.
- `store_password`: HKDF-SHA256(PRF) → the `cwst` store password.
- `ring_key`: HKDF-SHA256(PRF, other info) → the key that seals the key ring at rest.

## Storage

`ckmg` does no I/O. `KeyRing::seal_at_rest` returns the ring encrypted under the
PRF-derived `RingKey`; `cvlt` stores that blob in its `cwst` drawer. The ring is therefore
sealed twice at rest, and even code that can read the store cannot read ring secrets
without the passkey. (This also keeps `ckmg` free of private dependencies, so its CI runs
on hosted runners.)

## Boundaries

- No policy: `cvlt` decides who may call what, when pairing and root rotation happen.
- No export of root or device secrets; no backup; no recovery (invariant 6).
- No network code.
- Don't build primitives: only composition of upstream crates.

## Open points / TODO

- The architecture's cmsg table places the browser passkey half "inside `cvlt`"; the
  overnight brief placed it here. It lives in `ckmg::passkey` (a module cvlt drives);
  moving it is mechanical if Julian prefers `cvlt`.
- `passkey::browser` is type-checked for wasm32 in CI but not exercised: needs a
  headless-browser test with a virtual authenticator (queued vault prototype).
- VLD1 (Veilid's next cryptosystem) is not supported yet; `migrate` is the hook.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

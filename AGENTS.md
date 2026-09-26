# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Key drawer of the member vault (`cvlt`): root → device → purpose keys, VLD0 format,
  sign / verify / seal / open, delegation, pairing (root sealed to a new device), root
  rotation, passkey PRF → store password and ring key, WebAuthn registration and login.
- Invariant 5: root and device secrets never cross the public API. Only purpose keys may
  be delegated. The only way the root leaves is `seal_root_for_device` (pairing).
- No recovery, backup or export path. No policy (that is `cvlt`). No network code, no I/O.
- Never depend on `veilid-core`; use the crates Veilid's VLD0 uses and keep VLD0 semantics
  (Ed25519ph with context `VLD0_SIGN`, typed keys `VLD0:<base64url>`).
- Don't build security primitives: compose upstream crates.
- LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add code available only under the
  full GPL or AGPL. If code is copied from Veilid (MPL-2.0), keep it in its own file under
  MPL-2.0 with the upstream notice, as `cwst` does.
- Errors stay coarse: never include keys or plaintext.

## Layout

- `src/typed.rs`: `CryptoKind`, `PublicKey`, `Signature`, `HashDigest` (VLD0 typed format).
- `src/vld0.rs`: primitives on raw secrets (crate-private) plus public verify/seal/hash.
- `src/purpose.rs`: `Purpose`, `Scope`, `DelegatedKey`, `DelegatedSecret`, `Delegation`.
- `src/keyring.rs`: `KeyRing`, `KeyRef`, `RingKey`.
- `src/passkey.rs` (+ `passkey/browser.rs`, wasm32 only): WebAuthn with PRF.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
  `cargo clippy --lib --target wasm32-unknown-unknown -- -D warnings` — all green in CI
  (GitHub Actions). No local workstation builds.

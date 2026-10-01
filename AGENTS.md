# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Key drawer of the member vault (`cvlt`): root → device → purpose keys, VLD0 format,
  sign / verify / seal / open, delegation, pairing (root sealed to a new device), root
  rotation, PRF-derived wrapping/device capabilities and a retained random common
  identity root. Every enrolled passkey has equal recovery through its own wrapped
  copy; no passkey can recreate a lost common root from its PRF alone.
- Invariant 5: root and device secrets never cross the public API. Only purpose keys may
  be delegated. The only way the root leaves is `seal_root_for_device` (pairing).
- cpky Passkeys (device) alone talks to WebAuthn; ckyh Keyhole is the server.
  ckmg receives opaque PRF input; cwst receives only an opaque wrapping handle.
- No recovery beyond the passkey, backup service or plaintext key export. No policy (that is `cvlt`). No network code, no I/O.
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
- `src/purpose.rs`: `Purpose`, `Scope`; opaque capabilities and certificates live in keys/lineage.
- `src/keyring.rs`: private material and checkpoint encryption.
- `src/keys.rs`, `src/lineage.rs`, `src/ports.rs`: authorized custody and transactions.
- `src/passkey.rs`: opaque PRF input, wrapping/device derivation and private
  purpose derivation from the retained common root; no WebAuthn.
- `docs/CONSTRUCTIONS.md`, `docs/SECURITY-REVIEW.md`: references and review gates.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
  `cargo clippy --lib --target wasm32-unknown-unknown -- -D warnings` — all green in CI
  (GitHub Actions). No local workstation builds.

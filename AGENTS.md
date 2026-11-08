# ckmg — agent notes

Commands (repo root; work in a lane, never edit `~/agents/scratch/ws`; lane-wide checks run via `cargo xtask check/test`):
- `bash .ci/update-our-crates.sh` first: advances internal crates to newest main; the `--locked` gates below assume it
- `cargo fmt --all -- --check`
- `cargo clippy --locked --all-targets -- -D warnings`
- `cargo test --locked`
- `cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings`

Hard invariants (enforcing check after each):
- Root/device secrets never cross the public API; only purpose keys are delegated; the root leaves only via `seal_root_for_device` (pairing). Enforced by `tests/unit/delegation.rs` (`delegation_bytes_hold_no_root_identity_history_ring_or_prf_material`) + `compile_fail` doctests in `src/keys/delegation.rs`.
- VLD0 semantics hold: Ed25519ph with context `VLD0_SIGN`, typed keys `VLD0:<base64url>`. Enforced by `tests/unit/veilid_reference.rs` (`veilid_sign_hash_key_and_typed_format_conformance`).
- Errors stay coarse and never carry keys or plaintext. Enforced by `tests/it/keys.rs` (`diagnostics_and_ciphertexts_omit_private_metadata`).
- No privileged passkey: a PRF alone cannot recreate the common root; recordless `Derived` restore refuses. Enforced by `tests/it/keys.rs` (`a_passkey_does_not_determine_the_common_identity_root`, `restore_refuses_unavailable_wrong_prf_forged_authority_and_stale_revision`).
- Never depend on `veilid-core`; only the VLD0 crates Veilid uses. Enforced by `python3 .github/check-first-party.py` (CI dependency policy).

Pointers: `docs/CONTRACT.md`, `docs/CONSTRUCTIONS.md`, `docs/SECURITY-REVIEW.md`; custody in `src/keys.rs`, `src/lineage.rs`, `src/passkey.rs`; types in `src/typed.rs`.
LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only code; Veilid MPL-2.0 copies stay in their own file with the upstream notice.

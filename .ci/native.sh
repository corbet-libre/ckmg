#!/usr/bin/env bash
# Run the original native owner gates; full Wasm/browser/coverage stays in verify.
set -euo pipefail
python3 .github/check-first-party.py
rustc --version
cargo metadata --locked --format-version 1 > dependency-metadata.json
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --features wallet-engine --test record_recipient -- -D warnings
cargo test --locked --features wallet-engine --test record_recipient

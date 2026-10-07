#!/usr/bin/env bash
set -euo pipefail
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export CARGO_HTTP_USER_AGENT="${CARGO_HTTP_USER_AGENT:-dependency-ci}"
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"

python3 .github/check-first-party.py
rustc --version
cargo metadata --locked --format-version 1 > dependency-metadata.json
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings

version=$(jq -r '.packages[] | select(.name == "wasm-bindgen") | .version' dependency-metadata.json)
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
runner_tmp="${RUNNER_TEMP}/ckmg-wasm-runner"
mkdir -p "$runner_tmp"
cd "$runner_tmp"
curl -A 'ci-library-check' --fail --location --retry 3 --remote-name "$base/$archive"
curl -A 'ci-library-check' --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check
tar -xzf "$archive" --strip-components=1
echo "$PWD" >> "$GITHUB_PATH"
export PATH="$PWD:$PATH"
cd "$OLDPWD"
export CHROMEDRIVER="$(command -v chromedriver)"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
export WASM_BINDGEN_USE_BROWSER='1'
export WASM_BINDGEN_TEST_TIMEOUT='60'
cargo test --locked --target wasm32-unknown-unknown

rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
CARGO_PROFILE_TEST_OPT_LEVEL=0 "$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex '(/tests/|/tests\.rs$)' --json --output-path coverage.json 2>&1
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '(/tests/|/tests\.rs$)' --lcov --output-path coverage.lcov 2>&1
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '(/tests/|/tests\.rs$)' --text --output-path coverage.txt 2>&1
)
python3 .github/check-coverage.py coverage.json 2>&1 || true
python3 .github/test-source-coverage.py 2>&1
python3 .github/check-source-coverage.py coverage.lcov coverage.json coverage.txt 2>&1

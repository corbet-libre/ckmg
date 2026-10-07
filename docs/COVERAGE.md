# Coverage

CI resolves one fresh Cargo.lock and uses that snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. Only test harness
files (`tests/`, `tests/*.rs` modules and `tests.rs`) are omitted from the measured
source; their actual round trips still execute.

The acceptance metric is 100% of the emitted source line counters (DA) and branch
counters (BRDA) of the upstream LLVM LCOV report, merged over generic copies, from
the same execution as the raw JSON (`.github/check-source-coverage.py`, the gate the
other first-party libraries use). The coverage run sets
`CARGO_PROFILE_TEST_OPT_LEVEL=0` so no owned body is optimised away. The scenario tests
for every refusal live in `tests/refusals_*.rs` (public API) and `src/tests/` (crate
internal; they forge checkpoints, grants and lineages with the deterministic test
secrets to reach refusals that follow an approved authority check).

## Approved exclusions

`.github/coverage-exclusions.json` lists the only excluded source. Each entry pins the
exact source line, and branch entries also pin the SHA-256 of the whole file, so any
edit forces a review. An excluded line must actually be uncovered, so the entry cannot
outlive a test that starts covering it.

### unreachable-error-paths

Four defensive error paths are provably unreachable; no input can produce them.

| Source | Why no input can reach it |
|---|---|
| `src/keyring.rs:29` (`Material::derive`, `lineage_root(.., 1)?`) | `lineage_root` fails only for epoch 0 or an HKDF-SHA256 expansion beyond 255 blocks. The epoch is the constant 1 and the output is a fixed 32 bytes. |
| `src/keys.rs:525` (`restore_scope`, `lineage_root(.., anchor.epoch)?`) | The same two causes. `anchor.verify()` runs first in the same function and `Lineage::shape` refuses epoch 0, so a verified anchor never has epoch 0. |
| `src/keys.rs:773-774` (`prepare`, `sealed.len() > MAX_CHECKPOINT_BYTES`) | `encode_checkpoint` accepts a plaintext only when its metadata is at most `MAX_CHECKPOINT_BYTES - 64 - 69` bytes. The sealed record is 19 (header) + 24 (nonce) + 4 + metadata + 65 (material) + 16 (tag) bytes, at most `MAX_CHECKPOINT_BYTES - 5`. The size cannot exceed the bound once the earlier check passed. |

The same arithmetic is why the true arm of the size comparison at line 773 and its
`return` at line 774 are both listed.

A configured gate is not a coverage result. The raw report is retained on failure.

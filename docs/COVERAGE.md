# Coverage

CI resolves one fresh Cargo.lock and uses that snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. No production source
is excluded. Only test harness files (`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.

The coverage job exports raw JSON and LCOV from the same actual test execution.
The gate requires every emitted production DA line and BRDA branch to have a
nonzero counter, at 100% for both metrics. It cross-checks file inventories,
summaries and emitted branch locations against the companion JSON. Missing,
duplicate, empty or malformed evidence cannot pass. Raw JSON totals remain
as diagnostic evidence for generic instantiations; source coverage does not
claim every generic instantiation is covered. Both artifacts are retained on
failure. No production source exclusions are currently approved.

## Production source and browser measurement

Unit harnesses, historical derivation vectors and upstream reference compositions
live under tests/unit. Their original tests still execute; they do not increase
the production coverage denominator. The unchanged MPL notice stays with the
Veilid reference fixture. New random-root recovery is measured in the production
state machine, independently of legacy vector compatibility.

A separate wasm-coverage job follows the successful native source gate. It runs
the same actual Chrome tests with current nightly and exports raw JSON, LCOV and
annotated source from that execution. The same strict inventory checker requires
all emitted production lines and branches. A browser compile check is not this
evidence, and an unexecuted job remains an open requirement.

The test-only profiling adapter reuses the existing Storage harness and maintained
minicov upstream master. Current wasm-bindgen-test's optional built-in profiler is
not enabled: its minicov version targets an older LLVM profile format. The small
separate test dependency captures real counters after upstream tests finish, and
the original upstream profile handler must accept a nonempty upload. There is no
production profiling API, synthetic counter generation or compiler pin. The code
uses wasm-bindgen's documented experimental coverage mechanism:
https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/coverage.html

All five substantive jobs, including browser coverage, are required by the
metadata-only Dependabot merge guard. No source exclusion has been added.

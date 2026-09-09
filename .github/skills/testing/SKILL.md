---
name: testing
user-invocable: false
description: "Select, run, and write CCF unit, end-to-end, partition, compatibility, coverage, and Python SDK tests. Covers prerequisites, the tests.sh wrapper, test labels, and e2e registration."
---

# Testing

## Running tests

Follow the global validation policy for choosing relevant tests and reporting blockers. Before running tests, configure and build the affected targets using the documented development environment. The Copilot formatting/lint setup alone is not a full test environment.

From the repository root, enter the configured build directory (shown here as `build`). Use its generated `tests.sh` wrapper for e2e tests: it creates/activates a Python venv, installs the SDK and test dependencies, then invokes `ctest`. First-time setup requires Python venv support and network access; subsequent runs still invoke dependency installation.

```bash
cd build
./tests.sh -N                       # Discover registered tests; does not run them
./tests.sh -L '^unit$' --no-tests=error
./tests.sh -L '^e2e$' --no-tests=error
./tests.sh -L '^partitions$' --no-tests=error  # Requires NET_ADMIN
./tests.sh -VV --timeout 360 -R '^recovery_test$' --no-tests=error
```

Use `-R` for name regexes and `-L` for labels. `./tests.sh` without a filter runs all registered tests; do not make this the default for a small change. Pure C++ unit tests and test discovery may use `ctest` directly from the build directory without Python setup. Use `--no-tests=error` for execution so an empty selection is not mistaken for passing tests.

Labels include `unit`, `e2e`, `partitions`, `perf`, `benchmark`, `raft_scenario`, `suite`, `lts_compatibility`, `snp`, and CI routing labels `bucket_a`, `bucket_b`, `bucket_c`. Registration depends on build options; inspect the configured inventory rather than assuming a named test exists.

### Compatibility

For changes affecting older releases, configure the intended build directory with `-DLONG_TESTS=ON` (a CMake option, not just a shell variable), rebuild affected targets, then run from that directory:

```bash
./tests.sh -R '^lts_compatibility$' --no-tests=error
```

`LONG_TESTS` enables additional ledger compatibility coverage. This test is not registered with `SAN=ON`; use a suitable separate build rather than silently skipping it. It also needs access to older releases; report unavailable downloads as blockers.

### Python SDK

SDK tests are separate from e2e. From the repository root, in an activated Python venv meeting `python/pyproject.toml`'s Python requirement, install the SDK and pytest as the SDK CI job does:

```bash
uv pip install -e ./python pytest
cd python
pytest
```

Exit status 0 indicates success; report the selected tests and their actual result, not merely a successful setup step.

## Code coverage

Configure with `-DCOVERAGE=ON`, build instrumented targets, and run the selected tests. From that build directory, with `llvm-profdata` and `llvm-cov` available:

```bash
../scripts/coverage.sh                  # Print summary
../scripts/coverage.sh --html report/   # Generate HTML report
../scripts/coverage.sh --html report/ --json report/coverage.json
python3 ../scripts/coverage_report.py report/coverage.json
```

These paths assume `build` is immediately under the repository root. For another layout, use the actual path to `scripts/coverage.sh` while retaining the build working directory. The script consumes `.profraw` files and the generated `coverage_binaries.txt`; building alone does not produce coverage.

The JSON export contains LLVM's per-file line and branch counts with the same exclusions as the HTML report. `coverage_report.py` separates framework (`src/`, `include/`), sample (`samples/`) and other paths without dropping any paths from the combined total. For reports produced elsewhere, pass `--source-dir` with that report's source root.

After the coverage workflow's unit and e2e selection, use `coverage_report.py --check-instrumentation report/coverage.json` to require nonzero line coverage in representative implementation files and headers. This guard is intentionally opt-in for smaller local test selections. Its reporting tests use the standard library: `python3 scripts/tests/coverage_report_test.py` from the source root.

First-party C++ static libraries are instrumented, but only linked binaries are report inputs; archives are not counted a second time. Their coverage runtime link requirement also applies to consumers of installed instrumented libraries. Rust is not instrumented by the C++ coverage flags.

For a baseline, use a fresh coverage build/profile directory and record the source revision, build options and exact test selection. Targeted tests do not establish a full-suite baseline. Reports predating library instrumentation have a different denominator and are not directly comparable; including previously invisible code can lower the headline percentage.

## End-to-end test infrastructure

E2e tests use the infrastructure in `tests/infra/`. The key classes are:

- `infra.network.Network`: manages a multi-node network; use the existing `infra.network.network(...)` context-manager pattern for lifecycle cleanup.
- `infra.node.Node`: represents one node process.
- `infra.consortium.Consortium`: member governance operations.
- `infra.runner.ConcurrentRunner`: schedules `run_*(args)` functions, each owning its network.

## Writing e2e tests

Follow a nearby test for the same application. In `tests/e2e_logging.py`, individual test cases accept `(network, args)`, while `run(args)` creates/opens the network and calls those cases. Requirement decorators from `suite.test_requirements` express the case's prerequisites.

- Register the network-owning `run_*(args)` function with `ConcurrentRunner.add`, not a `(network, args)` case. The runner invokes its target with one argument.
- `ConcurrentRunner.add(prefix, target, **args_overrides)` already deep-copies arguments and assigns a distinct label. Prefer its overrides for separate configurations rather than duplicating that work. Deep-copy arguments and set a distinct label yourself only when manually creating an additional independent configuration outside that mechanism.
- Reuse network/client/governance helpers; assert observable behaviour and clean up through existing context managers.
- Ensure the case is called by a runner. For a new e2e executable entry point, follow existing CMake `add_e2e_test` registration, including its CI bucket. Run `scripts/test-buckets-checks.sh` from the repository root when changing inventory, and update `tests/ci-buckets.txt` only for intentional registration changes.

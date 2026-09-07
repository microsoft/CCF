# CCF Repository Copilot Instructions

CCF (Confidential Consortium Framework) is a replicated state machine for confidential, distributed applications.

## Task boundaries

- Answer questions and planning requests without editing files unless requested.
- Inspect the worktree before editing. Preserve existing user changes; ask before overwriting conflicting edits.
- Limit edits to the requested task and necessary tests/documentation. Do not fix unrelated failures, reformat unrelated files, or expand into adjacent refactors.
- When a PR resolves an issue, include `Closes #123` with the actual issue number in its description. Use a non-closing reference for partial work.

## Repository map

- `src/kv/`, `src/consensus/aft/`: transactional in-memory state, ledger replication, and the AFT consensus protocol.
- `src/node/node_state.h`, `src/service/`: node lifecycle and governance tables; member constitutions execute JavaScript against the KV.
- `src/endpoints/`, `src/js/`, `samples/`: C++ endpoint registries and embedded QuickJS applications.
- `src/crypto/`, `src/tls/`, `src/http/`: cryptography, TLS, and HTTP transport.
- `include/ccf/`: public C++ API; `src/ds/`: internal utilities.
- `tests/`, `tests/infra/`: Python e2e tests and network infrastructure; C++ unit tests live alongside implementation code.
- `python/`: Python SDK; `doc/`: Sphinx/RST documentation; `tla/`: formal specifications; `cmake/`: build helpers.

## Task-specific guidance

- For C/C++ changes, read [C/C++ conventions and library error handling](/.github/instructions/reviewing.instructions.md).
- Before selecting, running, or writing tests, load the [testing skill](/.github/skills/testing/SKILL.md).
- Before formatting or linting, load the [formatting-and-linting skill](/.github/skills/formatting-and-linting/SKILL.md).
- For user-facing API or behaviour changes, update existing documentation and follow the [changelog instructions](/.github/instructions/changelog.instructions.md). Link to existing documentation rather than duplicating it.

## Validation

- Run checks relevant to the changed files before pushing. For C++ changes, build affected targets and run relevant tests locally. Behaviour changes need regression tests, including e2e coverage for user-visible behaviour.
- For changes that may affect older releases, use the compatibility procedure in the testing skill.
- Run `scripts/ci-checks.sh` without auto-fix for full local validation when prerequisites are available. Targeted checks do not constitute a full-suite pass.
- Required CI checks, including applicable tests in `.github/workflows/ci.yml`, must pass before merge; local validation does not replace them.
- If a check is blocked by missing tools, network access, privileges, or resources, report the exact command, blocker, and checks still needed. Do not claim unrun checks passed or weaken checks to obtain a pass.

### Build prerequisites and commands

Use [development setup](/doc/contribute/build_setup.rst) and [building CCF](/doc/contribute/build_ccf.rst) for supported environments and dependencies. The Copilot setup workflow installs formatting/lint prerequisites only; it does not provision a full C++ build/test environment. The full checks include `test-buckets-checks.sh`, which requires a successful CMake configure.

From the repository root, after installing build prerequisites:

```bash
cmake -S . -B build -GNinja
cmake --build build
```

The default configuration is `RelWithDebInfo`. For a separate Debug build, select a different build directory and `-DCMAKE_BUILD_TYPE=Debug`; add `-DCLANG_TIDY=ON` only when clang-tidy is installed. Reuse existing build configuration intentionally rather than overwriting it.

### Documentation

For RST changes, build Sphinx from the repository root in a Python virtual environment with the documentation dependencies:

```bash
uv pip install -r doc/requirements.txt -r doc/historical_ccf_requirements.txt
sphinx-build --fail-on-warning -b html doc doc/html
```

### Python

- Reuse existing e2e helpers from `tests/infra/`; only extract new shared helpers when needed for the task.
- Add type annotations and docstrings to new or changed SDK interfaces in `python/`; do not retrofit unrelated code.

## Security and correctness

- Never commit credentials or production keys. New certificate/key fixtures must be freshly generated and clearly test-only.
- Use CCF's crypto APIs in `include/ccf/crypto/` rather than implementing cryptographic primitives.
- For consensus, KV, and crypto changes, trace affected commit/rollback, ownership, and failure paths before editing; cover the relevant invariants with regression tests.

## Reviews

- Report actionable issues introduced by the diff, with a code location, triggering condition, and consequence. Prioritise authentication/authorization, external input handling, cryptography, memory ownership, and failure paths.
- Leave mechanical formatting to existing checks; do not repeat their findings as inline review comments. For ASCII policy, `scripts/ascii-checks.sh` owns file coverage and exceptions. Review intentional non-ASCII exceptions for justification; uncovered accidental non-ASCII source is an explicit exception to the no-formatting-comments rule.
- Bash scripts with pipelines must enable `set -o pipefail`. For other shells, check support before recommending Bash-specific options.
- Include a "Custom instructions used" section in PR review summaries listing the repository instruction files actually loaded and applied. Cite the scoped error-handling instructions when reporting a violation of that policy.

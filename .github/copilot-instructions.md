# CCF Repository Copilot Instructions

- This document provides guidance for AI coding and review agents working in the CCF (Confidential Consortium Framework) repository
- **CCF** is an open-source framework for building secure, highly available, and performant applications focused on multi-party compute and data. It's designed for confidential, distributed systems running on secure hardware.

**Key directories**:

- `src/` - Core CCF implementation in C++ (consensus, crypto, KV store, HTTP, TLS, JavaScript runtime), including unit tests in subdirs
- `include/ccf/` - Public C++ API headers
- `tests/` - Python-based end-to-end test suite
- `python/` - CCF Python SDK and client libraries
- `doc/` - Sphinx-based RST documentation
- `3rdparty/` - Third-party dependencies

## Code changes

- Coding style is enforced by the `ci-checks.sh` script, which runs clang-format for C++ and black for Python.
- Linters and static analysis tools are also run as part of CI, clang-tidy for C++ and ruff for Python.
- Run `ci-checks.sh -f` to automatically apply fixes (formatting and supported lint fixes).
- `ci-checks.sh` must run successfully before any commit is pushed.
- Match the existing coding style for naming and casing conventions. This is not automatically enforced, so pay attention to surrounding code for guidance.

### Formatting and linting

`scripts/ci-checks.sh` orchestrates all formatting and linting checks by running individual scripts concurrently. You can run all checks at once, or run only the scripts relevant to the files you changed.

To run **all** checks with auto-fix: `scripts/ci-checks.sh -f`

To run **only the checks you need**, use the individual scripts below based on the file types you modified. When a script supports `-f`, you **must** use it to auto-fix issues. When `-f` is not available, run the script and read its error output to determine what changes are needed.

#### Scripts with auto-fix (`-f`)

These scripts accept a `-f` flag that automatically corrects issues. Always run them with `-f`:

| Script | Run with | File types | Tool |
|--------|----------|------------|------|
| `scripts/cpp-format-checks.sh` | `scripts/cpp-format-checks.sh -f` | `.h`, `.hpp`, `.cpp`, `.cc` in `include/`, `src/`, `samples/` | clang-format |
| `scripts/python-format-checks.sh` | `scripts/python-format-checks.sh -f` | `.py` in `tests/`, `python/`, `scripts/`, `tla/` | black |
| `scripts/python-lint-checks.sh` | `scripts/python-lint-checks.sh -f` | `.py` in `python/`, `tests/` | ruff |
| `scripts/prettier-checks.sh` | `scripts/prettier-checks.sh -f` | `.ts`, `.js`, `.md`, `.yaml`, `.yml`, `.json` (excludes `tests/sandbox/`) | prettier |
| `scripts/cmake-format-checks.sh` | `scripts/cmake-format-checks.sh -f` | `CMakeLists.txt` and `.cmake` files in `cmake/`, `samples/`, `src/`, `tests/` | cmake-format |
| `scripts/release-notes-checks.sh` | `scripts/release-notes-checks.sh -f` | Release notes in `CHANGELOG.md` | extract-release-notes.py |

#### Scripts without auto-fix

These scripts only report problems. Run them and read the error output to determine what manual changes are needed:

| Script | Run with | File types | What to look for in the output |
|--------|----------|------------|-------------------------------|
| `scripts/shellcheck-checks.sh` | `scripts/shellcheck-checks.sh` | `.sh` files (excludes `3rdparty/`) | shellcheck warnings and errors with line numbers and fix suggestions |
| `scripts/python-types-checks.sh` | `scripts/python-types-checks.sh` | `.py` in `python/` | mypy type errors with file, line number, and expected types |
| `scripts/includes-checks.sh` | `scripts/includes-checks.sh` | `.h` in `include/ccf/` | Private headers included from public headers, missing `namespace ccf`, or unused exported headers |
| `scripts/copyright-checks.sh` | `scripts/copyright-checks.sh` | All source files | Files missing or with incorrect copyright notice headers |
| `scripts/openapi-checks.sh` | `scripts/openapi-checks.sh` | `.json` in `doc/schemas/` | OpenAPI schema validation errors from swagger-cli |
| `scripts/todo-checks.sh` | `scripts/todo-checks.sh` | All tracked files | Unacceptable `TODO` or `FIXME` comments that must be removed or resolved |

#### Which scripts to run for each file type

| If you modified | Run these scripts |
|----------------|-------------------|
| C/C++ source or headers (`.h`, `.hpp`, `.cpp`, `.cc`) | `cpp-format-checks.sh -f`, `includes-checks.sh`, `copyright-checks.sh` |
| Python files (`.py`) | `python-format-checks.sh -f`, `python-lint-checks.sh -f`, `python-types-checks.sh`, `copyright-checks.sh` |
| TypeScript/JavaScript (`.ts`, `.js`) | `prettier-checks.sh -f`, `copyright-checks.sh` |
| Markdown (`.md`) | `prettier-checks.sh -f` |
| YAML (`.yaml`, `.yml`) | `prettier-checks.sh -f` |
| JSON (`.json`) | `prettier-checks.sh -f`, `openapi-checks.sh` (if in `doc/schemas/`) |
| CMake files (`CMakeLists.txt`, `.cmake`) | `cmake-format-checks.sh -f` |
| Shell scripts (`.sh`) | `shellcheck-checks.sh`, `copyright-checks.sh` |
| Release notes (`CHANGELOG.md`) | `release-notes-checks.sh -f`, `prettier-checks.sh -f` |
- All tests in `ci.yml` must pass before a PR can be merged. Consider which are likely to be affected by your changes and run those locally before pushing.
- Take particular care with any changes that may affect compatibility with older releases, and ensure these are tested, via the `lts_compatibility` test with `LONG_TESTS=1` enabled.
- Take particular care with changes to the consensus and crypto code, as these are critical for security and correctness. Ensure you have a thorough understanding of the existing code and the implications of your changes before proceeding.
- Any changes to user-facing APIs or behaviour must be documented in `CHANGELOG.md`. When adding a new version to `CHANGELOG.md`, be sure to update `pyproject.toml` to match.

### C++

- C++ changes must be built and tested locally before creating a PR. Use cmake and ninja to build, and refer to CI files for any further build configurations. For example:
  ```bash
  mkdir build && cd build
  cmake -GNinja ..          # RelWithDebInfo by default
  ninja                     # Build all targets
  ```
- Both unit tests and end-to-end tests can be run using ctest, but should be invoked via the `tests.sh` wrapper script to ensure the correct environment is set up and used. For example:
  ```bash
  cd build
  ./tests.sh              # Run all tests
  ./tests.sh -VV          # Verbose output
  ./tests.sh -R pattern   # Run tests matching pattern
  ```
- Most changes should be accompanied by new or updated tests. End-to-end tests are required for any changes that affect the user-visible behaviour.
- Use modern features where appropriate, but be wary of newer features that may not be fully supported.

### Python

- There are 2 kinds of Python code in the repository: the end-to-end tests (and supporting infra) in `tests/`, and the Python SDK in `python/`.
- Pay attention to existing helpers and utilities in the test suite when writing new tests, and avoid duplicating code. If you find yourself copying and pasting code, consider refactoring it into a shared helper function or class.
- All code in the SDK should include type annotations and docstrings.

### Documentation

- Any RST changes must be built with Sphinx to ensure they render correctly.
- Check for existing documentation on the topic before creating new docs, and provide thorough crosslinks where appropriate. Avoid duplicating information that already exists in the docs.
- For any user-facing changes, ensure that the documentation is updated to reflect the new behaviour.

### Security posture

- **No secrets in code**: Avoid committing API keys, passwords, or other secrets. Some certificates and keys are included in the repository for testing purposes, but if adding more ensure these are freshly created and properly documented as test-only artifacts.
- **Input validation**: Always validate and sanitize external inputs
- **Cryptographic operations**: Use CCF's crypto library (`include/ccf/crypto/`) - don't roll your own
- **Memory safety**: Use RAII, smart pointers, and avoid manual memory management

## Reviews

- Never comment on code formatting when performing code reviews.
- When shell scripts or bash scripts are created or modified, if they contain any use of the pipe (|) operator, they must also set the pipefail option (set -o pipefail). Remind the PR author if they have missed that.

### Code Review Security Focus

When reviewing code, pay special attention to:

- Authentication and authorization logic
- Cryptographic operations
- Input parsing and validation
- Memory management
- Error handling in security-critical paths

# CCF Repository Copilot Instructions

- This document provides guidance for AI coding and review agents working in the CCF (Confidential Consortium Framework) repository
- **CCF** is an open-source framework for building secure, highly available, and performant applications focused on multi-party compute and data. It's designed for confidential, distributed systems running on secure hardware.

**Key directories**:

- `src/` - Core CCF implementation in C++ (consensus, crypto, kv store, HTTP, TLS, JavaScript runtime), including unit tests in subdirs
- `include/ccf/` - Public C++ API headers
- `tests/` - Python-based end-to-end test suite
- `python/` - CCF Python SDK and client libraries
- `doc/` - Sphinx-based RST documentation
- `3rdparty/` - Third-party dependencies

## Code changes

- Coding style is enforced by the `ci-checks.sh` script, which runs clang-format for C++ and black for Python.
- Linters and static analysis tools are also run as part of CI, clang-tidy for C++ and ruff for Python.
- Run `ci-checks.sh -f` to automatically run these tools.
- This tool must run successfully before creating a PR.
- Match the existing coding style for naming and casing conventions. This is not automatically enforced, so pay attention to surrounding code for guidance.
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

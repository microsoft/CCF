# CCF Repository Copilot Instructions

This document provides guidance for AI coding agents working in the CCF (Confidential Consortium Framework) repository.

## Repository Overview

**CCF** is an open-source framework for building secure, highly available, and performant applications focused on multi-party compute and data. It's designed for confidential, distributed systems running on secure hardware.

**Primary languages**: C++ (core framework), TypeScript/JavaScript (application development), Python (testing and tooling)

**Key directories**:

- `src/` - Core CCF implementation (consensus, crypto, kv store, HTTP, TLS, JavaScript runtime)
- `include/ccf/` - Public API headers
- `tests/` - Python-based end-to-end test suite
- `python/` - CCF Python SDK and client libraries
- `doc/` - Sphinx-based documentation
- `samples/` - Sample CCF applications
- `cmake/` - CMake build configuration modules
- `3rdparty/` - Third-party dependencies

## Build System

### Prerequisites

- **OS**: Azure Linux 3 (recommended for development)
- **RAM**: 32GB+ recommended
- **Build tools**: CMake ≥3.21, Ninja, Clang
- **Setup scripts**: `scripts/setup-ci.sh` (CI dependencies) and `scripts/setup-dev.sh` (dev dependencies)

### Building CCF

Standard build process:

```bash
mkdir build && cd build
cmake -GNinja ..          # RelWithDebInfo by default
ninja                     # Build all targets
```

Common CMake options (see all with `cmake -L ..`):

- `BUILD_TESTS=ON/OFF` - Build test suite (default: ON)
- `CMAKE_BUILD_TYPE=Debug|Release|RelWithDebInfo` - Build configuration (default: RelWithDebInfo)
- `SAN=ON` - Enable Address and UBSan sanitizers
- `TSAN=ON` - Enable Thread Sanitizer
- `CLANG_TIDY=ON` - Enable static analysis during build (used in CI)
- `LONG_TESTS=ON` - Include long-running tests
- `USE_SNMALLOC=ON/OFF` - Use snmalloc allocator

### Important Build Notes

- **Memory**: Building with default compiler requires ~32GB RAM
- **Generator**: Always use Ninja (`-GNinja`) for consistency with CI
- **Parallel builds**: Ninja automatically parallelizes; be mindful of memory usage

## Testing

### Test Infrastructure

**C++ Unit Tests**:

- Framework: Doctest (`#include <doctest/doctest.h>`)
- Location: `src/*/test/*.cpp` files
- Macros: `TEST_CASE("description")`, `REQUIRE(condition)`, `CHECK(condition)`
- Run via: `ctest -L unit`

**Python End-to-End Tests**:

- Framework: pytest with custom test infrastructure in `tests/infra/`
- Location: `tests/*.py` (e2e*suite.py, governance.py, raft_scenarios*\*.py, etc.)
- Test infrastructure provides: network setup, node management, consortium operations
- Dependencies: See `tests/requirements.txt` (httpx, loguru, JWCrypto, etc.)

### Running Tests

**Recommended**: Use the test wrapper script which sets up Python virtual environment:

```bash
cd build
./tests.sh              # Run all tests
./tests.sh -VV          # Verbose output
./tests.sh -L unit      # Run only unit tests
./tests.sh -R pattern   # Run tests matching pattern
```

**Direct ctest usage** (for unit tests only):

```bash
ctest -L unit           # Unit tests only
ctest -L partitions     # Partition tests
```

**Important**: E2E tests require Python virtual environment set up by `tests.sh`. The venv is created in `build/env/` and reused on subsequent runs.

## Code Formatting and Linting

**All formatting checks are automated** via `scripts/ci-checks.sh`:

```bash
./scripts/ci-checks.sh     # Check all formatting (used in CI)
./scripts/ci-checks.sh -f  # Auto-fix formatting issues
```

**Individual tools**:

- **C/C++**: clang-format (config: `.clang-format`) - enforces consistent style
- **Python**:
  - `ruff` for linting (config: `.ruff.toml`, line length: 320)
  - Type checking with mypy
- **Web**: prettier for TypeScript, JavaScript, YAML, JSON, Markdown (config: `.prettierignore`)
- **CMake**: cmake-format (config: `.cmake-format.py`)
- **Shell**: shellcheck for all `.sh` files

**CI Enforcement**:

- All PRs must pass formatting checks before merge
- Run `./scripts/ci-checks.sh` locally before pushing to avoid CI failures
- The `-f` flag auto-fixes most issues

## Code Conventions and Patterns

### C++ Style

**Naming**:

- Namespaces: `ccf::`, `ccf::kv::`, `ccf::endpoints::`, etc. (nested hierarchical)
- Classes/Enums: PascalCase (e.g., `EndpointKey`, `TypedMap`)
- Enums: Use `enum class` for type safety
- Methods/Variables: snake_case (e.g., `uri_path`, `get_status()`)
- Member variables: snake_case with no prefix

**Logging**:

```cpp
// Use LOG_*_FMT macros (defined in ds/logger.h)
LOG_INFO_FMT("Message: {}", value);
LOG_DEBUG_FMT("Debug info");
LOG_FAIL_FMT("Error: {}", error_msg);
LOG_FATAL_FMT("Fatal error");
```

**Error Handling**:

- Use `RpcException` for RPC-related errors
- Use `std::logic_error` for programming errors
- Use `CCF_ASSERT()` for assertions (throws `std::logic_error` in debug builds)
- Mark important return values with `[[nodiscard]]`

**Modern C++ Features**:

- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- Use `constexpr` where applicable
- Use structured bindings for clearer code
- Use `std::optional` for nullable values
- Template-heavy design for generic KV store and maps

**File Headers**: Every source file must include:

```cpp
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
```

### Python Style

- Follow PEP 8 conventions
- Use type hints throughout
- Docstrings: Triple-quoted strings for functions/classes
- Naming: snake_case for functions/variables, PascalCase for classes
- Line length: 320 characters (enforced by ruff)
- Use `Enum` base class for enumerations
- Use `@dataclass` decorator where appropriate

### Static Analysis

**clang-tidy**: Enabled in CI builds (`CLANG_TIDY=ON`)

- Config: `.clang-tidy` (extensive checks enabled)
- Major check groups: bugprone, cert, concurrency, cppcoreguidelines, modernize, performance
- Many specific checks disabled for pragmatic reasons (see `.clang-tidy`)

**CodeQL**: Security analysis runs on PRs and weekly

- Workflow: `.github/workflows/codeql-analysis.yml`
- Focus: Security vulnerabilities and code quality issues

## Development Workflows

### DevContainer Support

VSCode devcontainer configuration available in `.devcontainer/`:

- Base image: Azure Linux 3.0
- Recommended specs: 16 CPU, 64GB RAM, 128GB storage
- Post-create script installs all dependencies
- Works with GitHub Codespaces

### CI Pipeline

Main workflow: `.github/workflows/ci.yml`

- Triggered on: PRs, weekly schedule, manual dispatch
- Stages: checks → build → unit tests → integration tests
- Uses: Self-hosted Azure VMs and container runners
- Builds with clang-tidy enabled for static analysis

Additional workflows:

- `long-test.yml` - Extended tests (ASAN, TSAN, fuzzing) - daily on weekdays
- `codeql-analysis.yml` - Security scanning - on PRs and weekly
- `ci-verification.yml` - Formal verification (TLA+) - on relevant changes
- `bencher.yml` - Performance benchmarking - on main branch commits

### Documentation

**Preview changes locally**:

```bash
./livehtml.sh              # Build and serve docs with live reload
SKIP_DOXYGEN=ON ./livehtml.sh  # Skip Doxygen (faster for doc-only changes)
```

**Documentation is built with Sphinx** and published to GitHub Pages.

## Common Issues and Gotchas

### Build Issues

1. **Memory exhaustion**: Building CCF requires significant RAM (~32GB). If builds fail with OOM:
   - Reduce parallel jobs: `ninja -j4` instead of default
   - Use `CMAKE_BUILD_TYPE=Debug` (smaller binary)
   - Disable sanitizers if enabled

2. **Missing dependencies**: Always run `scripts/setup-ci.sh` and `scripts/setup-dev.sh` after fresh checkout

3. **Stale build artifacts**: When switching branches or after major changes:
   ```bash
   rm -rf build && mkdir build && cd build
   cmake -GNinja .. && ninja
   ```

### Test Issues

1. **E2E test failures**: Ensure Python venv is set up correctly:

   ```bash
   cd build
   ./tests.sh  # This creates venv and installs dependencies
   ```

2. **Flaky tests**: Some tests involve networking and timing. If a test fails intermittently:
   - Check CI logs for patterns
   - Run locally multiple times to reproduce
   - Consider using `pytest -x` to stop on first failure

3. **Port conflicts**: E2E tests start local networks. If tests fail with port binding errors:
   - Kill any orphaned CCF processes: `pkill -f cchost`
   - Check for port conflicts: `netstat -tuln | grep <port>`

### Formatting Issues

1. **Formatting check failures in CI**: Always run locally before pushing:

   ```bash
   ./scripts/ci-checks.sh -f  # Auto-fix most issues
   ```

2. **False positives**: Some checks may flag false positives. Check the specific group that failed and investigate.

3. **Copyright headers**: All source files need copyright header. CI checks enforce this.

### Shell Script Requirements

**Critical**: When creating or modifying shell scripts that use pipes (`|`):

- **Must** set `set -o pipefail` at the top of the script
- This ensures pipe failures are caught (Bash normally only checks the last command in a pipe)
- Example:

  ```bash
  #!/bin/bash
  set -e
  set -o pipefail  # Required when using pipes!

  cat file.txt | grep pattern | process
  ```

## Security Considerations

### Reporting Security Issues

**Never report security vulnerabilities through public GitHub issues.**

- Report to Microsoft Security Response Center (MSRC): https://msrc.microsoft.com/create-report
- Or email: secure@microsoft.com
- See `SECURITY.md` for full details

### Security Best Practices

1. **No secrets in code**: Never commit API keys, passwords, certificates, or other secrets
2. **Input validation**: Always validate and sanitize external inputs
3. **Cryptographic operations**: Use CCF's crypto library (`include/ccf/crypto/`) - don't roll your own
4. **Memory safety**: Use RAII, smart pointers, and avoid manual memory management
5. **Static analysis**: Enable sanitizers and clang-tidy for development builds
6. **Dependencies**: Security scanning runs via CodeQL and dependency audits

### Code Review Security Focus

When reviewing code, pay special attention to:

- Authentication and authorization logic
- Cryptographic operations
- Input parsing and validation
- Memory management
- Error handling in security-critical paths

## CI/CD and Pull Requests

### PR Requirements

1. **CLA**: Contributors must sign Microsoft CLA (automated via bot)
2. **From fork**: All PRs must come from a fork, not a branch on main repo
3. **CI must pass**: All checks in `ci.yml` must succeed
4. **Formatting**: Must pass `scripts/ci-checks.sh` checks
5. **Code review**: At least one approving review required

### Triggering Extended Tests

- **Long tests**: Add label `run-long-test` to PR (runs ASAN/TSAN builds)
- **Verification**: Add label `run-long-verification` to PR (runs extended model checking)
- **Benchmarks**: Add label `bench-ab` to PR (runs performance comparison vs main)

### Useful Git Commands

```bash
# Check what will be committed
git status
git diff

# See recent commits
git log --oneline -10

# Check formatting without modifying files
./scripts/ci-checks.sh

# Auto-fix formatting
./scripts/ci-checks.sh -f
```

## Repository-Specific Tools and Patterns

### CCF Application Development

Applications can be written in:

- **TypeScript/JavaScript**: Using QuickJS runtime embedded in CCF
- **C++**: Using CCF C++ API

See `samples/` for examples and `doc/build_apps/` for guides.

### Key CMake Modules

Located in `cmake/`:

- `ccf_app.cmake` - Application compilation helpers
- `crypto.cmake` - Cryptographic library setup
- `quickjs.cmake` - JavaScript engine integration
- `snmalloc.cmake` - Memory allocator configuration
- `t_cose.cmake`, `qcbor.cmake` - COSE signing support

### Python Test Infrastructure

Key modules in `tests/infra/`:

- `network.py` - Network and node management
- `consortium.py` - Governance operations
- `clients.py` - HTTP client utilities
- `runner.py` - Test execution framework

### Logging in Tests

Python tests use `loguru` for logging. E2E framework provides rich logging with context.

## Code Review Guidelines

Never comment on code formatting when performing code reviews - formatting is enforced by CI.

When shell scripts or bash scripts are created or modified, if they contain any use of the pipe (|) operator, they must also set the pipefail option (set -o pipefail). Remind the PR author if they have missed that.

Focus reviews on:

- Correctness and logic errors
- Security implications
- Performance considerations
- API design and usability
- Test coverage
- Documentation completeness

## Quick Reference

### Common Commands

```bash
# Setup
./scripts/setup-ci.sh
./scripts/setup-dev.sh

# Build
mkdir build && cd build
cmake -GNinja ..
ninja

# Test
./tests.sh
./tests.sh -VV  # Verbose

# Format
./scripts/ci-checks.sh -f

# Documentation
./livehtml.sh
```

### Important Files

- `CMakeLists.txt` - Main build configuration
- `.github/workflows/ci.yml` - CI pipeline definition
- `tests/tests.sh` - Test runner wrapper
- `scripts/ci-checks.sh` - Formatting and linting
- `.clang-format`, `.clang-tidy`, `.ruff.toml` - Code style configs
- `tests/requirements.txt` - Python test dependencies
- `doc/contribute/` - Contributor documentation

### Getting Help

- Documentation: https://microsoft.github.io/CCF/
- Issues: https://github.com/microsoft/CCF/issues
- Discussions: https://github.com/microsoft/CCF/discussions
- Contributing guide: `.github/CONTRIBUTING.md`

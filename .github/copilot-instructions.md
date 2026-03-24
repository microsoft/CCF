# CCF Repository Copilot Instructions

- This document provides guidance for AI coding and review agents working in the CCF (Confidential Consortium Framework) repository
- **CCF** is an open-source framework for building secure, highly available, and performant applications focused on multi-party compute and data. It's designed for confidential, distributed systems running on secure hardware.

## Architecture

CCF is a replicated state machine where application state lives in an in-memory **key-value store** (`src/kv/`). Writes are serialised to an append-only **ledger** and replicated across nodes via the **AFT consensus protocol** (a Raft variant in `src/consensus/aft/`). The node lifecycle — startup, join, recovery, reconfiguration — is managed by the **node state machine** (`src/node/node_state.h`).

Applications are either **C++ endpoint registries** (subclassing `ccf::UserEndpointRegistry`) or **JavaScript/TypeScript bundles** executed by an embedded QuickJS runtime (`src/js/`). Both register HTTP endpoints that read/write the KV store through transaction objects (`ccf::Tx`).

Governance is handled by a built-in **member-driven constitution** system — proposals are submitted as JavaScript and executed against the KV. The crypto subsystem (`src/crypto/`, `include/ccf/crypto/`) wraps OpenSSL for TLS, x.509, COSE signatures, and Merkle tree operations.

**Key directories**:

- `src/` — Core C++ implementation, including unit tests in subdirectories
  - `consensus/aft/` — AFT (Raft variant) consensus protocol
  - `kv/` — Replicated key-value store and transaction machinery
  - `node/` — Node state machine, governance, historical queries, snapshots
  - `crypto/` — Cryptographic primitives (OpenSSL wrappers, COSE, Merkle)
  - `endpoints/` — HTTP endpoint registration and dispatch
  - `js/` — QuickJS-based JavaScript runtime for JS applications
  - `http/` — HTTP/1.1 and HTTP/2 parser and session management
  - `tls/` — TLS session handling
  - `ds/` — Data structures and utilities (logging, serialisation helpers)
  - `service/` — Internal service tables and governance tables
- `include/ccf/` — Public C++ API headers (the stable interface for app developers)
- `tests/` — Python-based end-to-end test suite and infrastructure (`tests/infra/`)
- `python/` — CCF Python SDK (ledger parsing, COSE signing, receipts)
- `doc/` — Sphinx-based RST documentation
- `samples/` — Example C++ and JS applications
- `tla/` — TLA+ formal specifications for consensus and disaster recovery
- `cmake/` — CMake build helpers (`common.cmake`, `ccf_app.cmake`)

## Build, test, and lint

### Building

```bash
mkdir build && cd build
cmake -GNinja ..                           # RelWithDebInfo by default
cmake -GNinja -DCMAKE_BUILD_TYPE=Debug ..  # Debug with clang-tidy: add -DCLANG_TIDY=ON
ninja                                      # Build all targets
```

### Testing

Tests must be run via the `tests.sh` wrapper (in the build directory), which sets up a Python venv, installs the SDK and test dependencies, then invokes `ctest`:

```bash
cd build
./tests.sh                          # Run all tests
./tests.sh -VV                      # Verbose output
./tests.sh -R <pattern>             # Run tests matching a name regex
./tests.sh -L unit                  # Run only unit tests
./tests.sh -L e2e                   # Run only end-to-end tests
./tests.sh -L partitions            # Run partition tests (requires NET_ADMIN)
./tests.sh --timeout 360 -R recovery_test  # Single e2e test with timeout
```

Test labels: `unit`, `e2e`, `partitions`, `perf`, `benchmark`, `raft_scenario`, `suite`, `lts_compatibility`, `snp`.

Python SDK tests (separate from e2e):

```bash
cd python && pytest
```

### Linting and formatting

```bash
scripts/ci-checks.sh        # Run all checks (concurrent)
scripts/ci-checks.sh -f     # Auto-fix formatting and supported lint issues
```

This runs 12 checks concurrently: clang-format (C++), black (Python), ruff (Python lint), mypy (Python types), shellcheck, prettier (JS/TS/MD/YAML/JSON), cmake-format, copyright headers, include hygiene, OpenAPI schema validation, release notes, and TODO format.

### Documentation

```bash
pip install -r doc/requirements.txt -r doc/historical_ccf_requirements.txt
sphinx-build --fail-on-warning -b html doc doc/html
```

### Code coverage

Build with `-DCOVERAGE=ON`, run tests, then:
```bash
scripts/coverage.sh                  # Print summary
scripts/coverage.sh --html report/   # Generate HTML report
```

## Code changes

- `ci-checks.sh` must run successfully before any commit is pushed.
- All tests in `ci.yml` must pass before a PR can be merged. Consider which are likely to be affected by your changes and run those locally before pushing.
- Take particular care with any changes that may affect compatibility with older releases, and ensure these are tested, via the `lts_compatibility` test with `LONG_TESTS=1` enabled.
- Take particular care with changes to the consensus and crypto code, as these are critical for security and correctness. Ensure you have a thorough understanding of the existing code and the implications of your changes before proceeding.
- Any changes to user-facing APIs or behaviour must be documented in `CHANGELOG.md` (Keep a Changelog format, under the current `[Unreleased]` or dev version, in `Added`/`Changed`/`Fixed`/`Removed` sections). When adding a new version to `CHANGELOG.md`, be sure to update `python/pyproject.toml` to match.

### C++

- C++ changes must be built and tested locally before creating a PR.
- Most changes should be accompanied by new or updated tests. End-to-end tests are required for any changes that affect the user-visible behaviour.

#### Naming conventions

- **Classes/structs**: `PascalCase` (`EndpointRegistry`, `TypedMap`, `NodeState`)
- **Methods/functions**: `snake_case` (`make_endpoint`, `set_auto_schema`, `get_path_param`)
- **Member variables**: `snake_case`, no prefix (`uri_path`, `forwarding_required`)
- **Constants**: `UPPER_SNAKE_CASE` (`PRIVATE_RECORDS`, `JOIN_TIMEOUT`)
- **Namespaces**: `snake_case` (`ccf::kv`, `ccf::endpoints`, `ccf::crypto`)
- **Files**: `snake_case` (`node_state.h`, `endpoint_registry.cpp`)
- **Header guards**: Always `#pragma once`, never `#ifndef`

#### JSON serialisation

Use the `DECLARE_JSON_*` macros from `ccf/ds/json.h` for struct serialisation:

```cpp
DECLARE_JSON_TYPE(MyStruct);
DECLARE_JSON_REQUIRED_FIELDS(MyStruct, field_a, field_b);

DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(MyConfig);
DECLARE_JSON_REQUIRED_FIELDS(MyConfig, name);
DECLARE_JSON_OPTIONAL_FIELDS(MyConfig, description, timeout);

DECLARE_JSON_TYPE_WITH_BASE(DerivedType, BaseType);
DECLARE_JSON_REQUIRED_FIELDS(DerivedType, extra_field);
```

#### Endpoint registration

Endpoints are registered in `init_handlers()` using a fluent builder pattern:

```cpp
make_endpoint("/records/{key}", HTTP_PUT, handler, {ccf::user_cert_auth_policy})
  .set_auto_schema<RequestType, ResponseType>()
  .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
  .install();

make_read_only_endpoint("/records/{key}", HTTP_GET, ro_handler, {ccf::user_cert_auth_policy})
  .install();
```

Use `make_endpoint` for read-write, `make_read_only_endpoint` for read-only, and `make_command_endpoint` for operations that don't access the KV store.

#### Logging

Use the macro-based logging system. For application code:

```cpp
CCF_APP_INFO("Processing request for key {}", key);   // INFO level, "app" tag
CCF_APP_FAIL("Failed to process: {}", error_msg);      // FAIL level
CCF_APP_TRACE("Debug detail: {}", detail);              // TRACE level
```

For framework-internal code, use `LOG_INFO_FMT`, `LOG_DEBUG_FMT`, `LOG_FAIL_FMT`, `LOG_FATAL_FMT` (from `src/ds/internal_logger.h`). Log levels in order of decreasing verbosity: `TRACE`, `DEBUG`, `INFO`, `FAIL`, `FATAL`.

#### KV store

Maps are typed with key/value serialisers and accessed through transaction handles:

```cpp
using MyMap = ccf::kv::Map<std::string, std::vector<uint8_t>>;
auto* handle = ctx.tx.template rw<MyMap>("my_map");  // Read-write handle
handle->put(key, value);
auto val = handle->get(key);  // Returns std::optional
```

### Python

- There are 2 kinds of Python code in the repository: the end-to-end tests (and supporting infra) in `tests/`, and the Python SDK in `python/`.
- Pay attention to existing helpers and utilities in the test suite when writing new tests, and avoid duplicating code. If you find yourself copying and pasting code, consider refactoring it into a shared helper function or class.
- All code in the SDK should include type annotations and docstrings.

#### End-to-end test patterns

E2e tests use the infrastructure in `tests/infra/`. The key classes are:
- `infra.network.Network` — manages a multi-node CCF network (start, stop, find primary/backup, add/remove nodes)
- `infra.node.Node` — represents a single CCF node process
- `infra.consortium.Consortium` — member governance operations (proposals, votes)
- `infra.runner.ConcurrentRunner` — runs multiple test functions against separate networks in parallel

Test functions take `(network, args)` parameters and are decorated with requirement annotations:

```python
@reqs.description("Write/Read messages on primary")
@reqs.supports_methods("/app/log/private")
@reqs.at_least_n_nodes(2)
def test_example(network, args):
    primary, _ = network.find_primary()
    with primary.client("user0") as c:
        r = c.post("/app/log/private", body={"id": 42, "msg": "hello"})
        assert r.status_code == http.HTTPStatus.OK
    return network
```

Tests are assembled in `ConcurrentRunner` at the bottom of test files:

```python
if __name__ == "__main__":
    cr = ConcurrentRunner()
    cr.add("test_name", test_function, package="samples/apps/logging/logging", nodes=...)
    cr.run()
```

When a test needs its own network configuration, deep-copy `const_args`, set a distinct `args.label`, and create a standalone `Network` in a separate `run_*` function.

### Documentation

- Any RST changes must be built with Sphinx to ensure they render correctly.
- Check for existing documentation on the topic before creating new docs, and provide thorough crosslinks where appropriate. Avoid duplicating information that already exists in the docs.
- For any user-facing changes, ensure that the documentation is updated to reflect the new behaviour.

### Security posture

- **No secrets in code**: Avoid committing API keys, passwords, or other secrets. Some certificates and keys are included in the repository for testing purposes, but if adding more ensure these are freshly created and properly documented as test-only artifacts.
- **Input validation**: Always validate and sanitize external inputs
- **Cryptographic operations**: Use CCF's crypto library (`include/ccf/crypto/`) — don't roll your own
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

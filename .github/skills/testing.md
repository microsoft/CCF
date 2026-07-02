---
name: Testing
description: How to run unit tests, end-to-end tests, and Python SDK tests. Covers test labels, the tests.sh wrapper, e2e test infrastructure, and patterns for writing new tests.
---

# Testing

## Running tests

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

## Code coverage

Build with `-DCOVERAGE=ON`, run tests, then:

```bash
scripts/coverage.sh                  # Print summary
scripts/coverage.sh --html report/   # Generate HTML report
```

## End-to-end test infrastructure

E2e tests use the infrastructure in `tests/infra/`. The key classes are:

- `infra.network.Network` — manages a multi-node CCF network (start, stop, find primary/backup, add/remove nodes)
- `infra.node.Node` — represents a single CCF node process
- `infra.consortium.Consortium` — member governance operations (proposals, votes)
- `infra.runner.ConcurrentRunner` — runs multiple test functions against separate networks in parallel

## Writing e2e tests

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

# End-to-End Tests

## Test hierarchy

```
CTest entry          ctest -R e2e_logging
└── Entry-point      tests/e2e_logging.py
    └── Runner       cr.add("cpp", run_cpp, ...)
        └── Group    run_cpp(args) — creates and owns a network
            └── Case test_historical_query(network, args) — single test
```

## Naming conventions

### CTest entries

Registered in CMakeLists.txt via `add_e2e_test(NAME ...)`. Names should be
unique and not be substrings of each other, so that `ctest -R <name>` matches
exactly one test. For example, `recovery_test` and `recovery_test_suite` are
problematic because `-R recovery_test` matches both.

### Entry-points

Python scripts (e.g. `schema.py`, `e2e_logging.py`) that use `ConcurrentRunner`
to run one or more groups in parallel. A single entry-point may bin-pack
unrelated groups for efficient CI run-time.

### Runners (ConcurrentRunner threads)

The first argument to `cr.add("name", ...)`. This name appears in every log
line from that thread, so it should be short and descriptive (e.g. `"cpp"`,
`"operations"`, `"recovery"`).

### Groups — `run_` prefix

Top-level functions that create and own a network, then call test cases on it.

- Should take `(args)` or `(const_args)`.
- Should create their own network via `with infra.network.network(...)`.
- Should not return `network`.
- `const_args` signals the function will `copy.deepcopy` before mutating.

### Test cases — `test_` prefix

Individual test functions that operate on an existing network.

- Should take `(network, args)` and return `network` (enables chaining).
- Should have a `@reqs.description("...")` decorator.
- Should not create their own network.

### Other helpers

Functions that don't fit either pattern (e.g. shared test groups that operate
on an existing network but aren't individual tests) should avoid the `test_`
and `run_` prefixes.

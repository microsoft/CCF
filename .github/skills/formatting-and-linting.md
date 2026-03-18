---
name: Formatting and linting
description: How to run the individual formatting and linting check scripts, which support auto-fix, and which scripts to use for each file type.
---

# Formatting and linting

`scripts/ci-checks.sh` orchestrates all formatting and linting checks by running individual scripts concurrently. You can run all checks at once, or run only the scripts relevant to the files you changed.

To run **all** checks with auto-fix: `scripts/ci-checks.sh -f`

To run **only the checks you need**, use the individual scripts below based on the file types you modified. When a script supports `-f`, you **must** use it to auto-fix issues. When `-f` is not available, run the script and read its error output to determine what changes are needed.

## Scripts with auto-fix (`-f`)

These scripts accept a `-f` flag that automatically corrects issues. Always run them with `-f`:

| Script                            | Run with                             | File types                                                                    | Tool                     |
| --------------------------------- | ------------------------------------ | ----------------------------------------------------------------------------- | ------------------------ |
| `scripts/cpp-format-checks.sh`    | `scripts/cpp-format-checks.sh -f`    | `.h`, `.hpp`, `.c`, `.cpp`, `.cc` in `include/`, `src/`, `samples/`           | clang-format             |
| `scripts/python-format-checks.sh` | `scripts/python-format-checks.sh -f` | `.py` in `tests/`, `python/`, `scripts/`, `tla/`                              | black                    |
| `scripts/python-lint-checks.sh`   | `scripts/python-lint-checks.sh -f`   | `.py` in `python/`, `tests/`                                                  | ruff                     |
| `scripts/prettier-checks.sh`      | `scripts/prettier-checks.sh -f`      | `.ts`, `.js`, `.md`, `.yaml`, `.yml`, `.json` (excludes `tests/sandbox/`)     | prettier                 |
| `scripts/cmake-format-checks.sh`  | `scripts/cmake-format-checks.sh -f`  | `CMakeLists.txt` and `.cmake` files in `cmake/`, `samples/`, `src/`, `tests/` | cmake-format             |
| `scripts/release-notes-checks.sh` | `scripts/release-notes-checks.sh -f` | Release notes in `CHANGELOG.md`                                               | extract-release-notes.py |

## Scripts without auto-fix

These scripts only report problems. Run them and read the error output to determine what manual changes are needed:

| Script                           | Run with                         | File types                                         | What to look for in the output                                                                                                         |
| -------------------------------- | -------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `scripts/shellcheck-checks.sh`   | `scripts/shellcheck-checks.sh`   | `.sh` files (excludes `3rdparty/`)                 | shellcheck warnings and errors with line numbers and fix suggestions                                                                   |
| `scripts/python-types-checks.sh` | `scripts/python-types-checks.sh` | `.py` in `python/`                                 | mypy type errors with file, line number, and expected types                                                                            |
| `scripts/includes-checks.sh`     | `scripts/includes-checks.sh`     | Public headers under `include/ccf/` (`.h`, `.hpp`) | Public/private include violations in files under `include/ccf/`, missing `namespace ccf` in public headers, or unused exported headers |
| `scripts/copyright-checks.sh`    | `scripts/copyright-checks.sh`    | All source files                                   | Files missing or with incorrect copyright notice headers                                                                               |
| `scripts/openapi-checks.sh`      | `scripts/openapi-checks.sh`      | `.json` in `doc/schemas/`                          | OpenAPI schema validation errors from swagger-cli                                                                                      |
| `scripts/todo-checks.sh`         | `scripts/todo-checks.sh`         | All tracked files                                  | Unacceptable comments that must be removed or resolved                                                                                 |

## Which scripts to run for each file type

| If you modified                                             | Run these scripts                                                                                         |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| C/C++ source or headers (`.h`, `.hpp`, `.c`, `.cpp`, `.cc`) | `cpp-format-checks.sh -f`, `includes-checks.sh`, `copyright-checks.sh`                                    |
| Python files (`.py`)                                        | `python-format-checks.sh -f`, `python-lint-checks.sh -f`, `python-types-checks.sh`, `copyright-checks.sh` |
| TypeScript/JavaScript (`.ts`, `.js`)                        | `prettier-checks.sh -f`, `copyright-checks.sh`                                                            |
| Markdown (`.md`)                                            | `prettier-checks.sh -f`                                                                                   |
| YAML (`.yaml`, `.yml`)                                      | `prettier-checks.sh -f`                                                                                   |
| JSON (`.json`)                                              | `prettier-checks.sh -f`, `openapi-checks.sh` (if in `doc/schemas/`)                                       |
| CMake files (`CMakeLists.txt`, `.cmake`)                    | `cmake-format-checks.sh -f`                                                                               |
| Shell scripts (`.sh`)                                       | `shellcheck-checks.sh`, `copyright-checks.sh`                                                             |
| Release notes (`CHANGELOG.md`)                              | `release-notes-checks.sh -f`, `prettier-checks.sh -f`                                                     |

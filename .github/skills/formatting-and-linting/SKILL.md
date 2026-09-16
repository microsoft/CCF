---
name: formatting-and-linting
user-invocable: false
description: "Format and lint CCF changes. Use when choosing or running checks for C++, Python, TypeScript, JavaScript, Markdown, YAML, JSON, CMake, shell scripts, or release notes, and when deciding which checks support automatic fixes."
---

# Formatting and linting

## Scope and prerequisites

Run commands from the repository root. `scripts/ci-checks.sh` runs the individual checks concurrently, including a build-configuration check. Use the global instructions' validation policy to choose targeted local checks or the full suite.

The Copilot setup workflow runs `scripts/setup-ubuntu-ci-checks.sh` for Ubuntu formatting/lint prerequisites. Some checks use `uvx` or npm to obtain tools at runtime and need network access. The test-bucket check additionally requires the full CMake configure prerequisites; the setup workflow does not install those.

## Check first, fix only task-owned changes

- Run scripts without `-f` initially. Success is exit status 0; inspect failure output to distinguish changed-file issues, unrelated failures, and environment blockers.
- The scripts generally scan whole directories or tracked files, not just the diff. Selecting a script by file type does not restrict which files it may rewrite.
- For auto-fix, use the existing underlying formatter/linter with explicit changed-file paths and the same version/configuration used by the script. Only fix files or hunks owned by the task; preserve existing user edits.
- Use a script's `-f` mode only after verifying its complete write scope is intended. Do not run repository-wide auto-fix as a default.
- Inspect the resulting diff and rerun the applicable check. Do not remove unrelated edits to make checks pass. Report blockers and unrelated failures under the global validation policy.

## Check inventory

Each command below is under `scripts/`. This table is a routing guide; the scripts own exact file coverage, exclusions, tool versions, and options. When changing that coverage, update this guide too. Include cross-cutting checks (copyright, disallowed comments, ASCII) when applicable.

| Script                    | Relevant changes                                             | Tool/check                                         | Supports auto-fix |
| ------------------------- | ------------------------------------------------------------ | -------------------------------------------------- | ----------------- |
| `cpp-format-checks.sh`    | C/C++ in `include/`, `src/`, `samples/`                      | clang-format                                       | `-f`              |
| `python-format-checks.sh` | Python in `tests/`, `python/`, `scripts/`, `tla/`            | black                                              | `-f`              |
| `python-lint-checks.sh`   | Python in `python/`, `tests/`                                | ruff                                               | `-f`              |
| `python-types-checks.sh`  | Python SDK                                                   | mypy                                               | No                |
| `prettier-checks.sh`      | TS, JS, Markdown, YAML, JSON (excluding `tests/sandbox/`)    | prettier                                           | `-f`              |
| `cmake-format-checks.sh`  | CMake files                                                  | gersemi                                            | `-f`              |
| `release-notes-checks.sh` | `CHANGELOG.md` (also run prettier)                           | extract-release-notes.py                           | `-f`              |
| `shellcheck-checks.sh`    | Shell scripts outside `3rdparty/`                            | shellcheck                                         | No                |
| `includes-checks.sh`      | Public C++ headers and their uses                            | Public/private include and exported-header checks  | No                |
| `copyright-checks.sh`     | Source files                                                 | Copyright notices                                  | No                |
| `openapi-checks.sh`       | JSON under `doc/schemas/`                                    | openapi-spec-validator                             | No                |
| `todo-checks.sh`          | Tracked files                                                | Disallowed comments                                | No                |
| `ascii-checks.sh`         | Source/config files and agent-instruction Markdown           | ASCII policy and grandfathered Unicode lines       | No                |
| `ascii-policy-tests.sh`   | ASCII policy/checker changes                                 | ASCII policy regression tests                      | No                |
| `test-buckets-checks.sh`  | CMake test registration, defaults, or `tests/ci-buckets.txt` | Fresh configure and CI bucket inventory comparison | No                |

Some report-only scripts accept `-f` for interface compatibility without changing files. For Rust or other file types not covered by a formatter above, consult their existing build/CI configuration rather than introducing a new tool.

The ASCII check includes Rust and TLA+, but exempts Lean source files (`*.lean`). Existing Unicode is grandfathered by exact line hashes, not file-wide exemptions. Do not extend the grandfathered hashes to accept new Unicode.

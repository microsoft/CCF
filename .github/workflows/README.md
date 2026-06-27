Documents the various GitHub Actions workflows, the role they fulfill and 3rd party (i.e. outside of https://github.com/actions/) dependencies if any.

# Maintained

## Bencher

Builds and runs CCF performance tests, both end to end and micro-benchmarks. Results are stored as artifacts and summarized in the workflow run.
Triggered on every commit on `main`, twice daily on week days, and manually, but not on PR builds because the setup required to build from forks is complex and fragile in terms of security, and the increase in pool usage would be substantial.

Tests are run on two different testbeds for comparison: gha-vmss-d16av6-ci (d16av6 VMs) and gha-c-aci-ci (C-ACI with 16 cores and 32Gb RAM).

File: `bencher.yml`
3rd party dependencies: None

## Bencher A/B

Builds and runs CCF performance tests, and performs a comparison to main. Triggered on PRs that have the label `bench-ab`.

File: `bencher-ab.yml`
3rd party dependencies: None

## Copilot Setup Steps

Sets up dependencies for the Copilot coding agent. Triggered when the workflow or setup script changes, and manually.

File: `copilot-setup-steps.yml`
3rd party dependencies: None

# Continuous Integration

Main continuous integration job. Builds CCF for all target platforms, runs unit, end to end and partition tests. Runs on PRs, merge queue runs, manually, and once a week, regardless of commits.

File: `ci.yml`
3rd party dependencies: None

# Coverage

Builds CCF with coverage enabled, runs unit and end to end tests, and uploads HTML coverage reports. Triggered on every commit on `main`, twice daily on week days, and manually.

File: `coverage.yml`
3rd party dependencies: None

# Long Tests

Secondary continuous integration job. Runs more expensive, longer tests, such as tests against ASAN and TSAN builds, extended fuzzing etc.

- Runs daily on week days.
- Can be manually run on a PR by setting `run-long-test` label, or via workflow dispatch.

File: `long-test.yml`
3rd party dependencies: None

# CodeQL analysis

Builds CCF with CodeQL, and runs the security-extended checks. Triggered on PRs that affect ".github/workflows/codeql-analysis.yml", on pushes to main, once a week on schedule, and manually.

File: `codeql-analysis.yml`
3rd party dependencies:

- `github/codeql-action/init@v4`
- `github/codeql-action/analyze@v4`

# Continuous Verification

Runs quick verification jobs: trace validation, simulation and short model checking configurations. Triggered on PRs that affect tla/, src/consensus, tests/raft_scenarios, or the workflow itself, weekly, and manually.

File: `ci-verification.yml`
3rd party dependencies: None

# Long Verification

Runs more expensive verification jobs, such as model checking with reconfiguration.

- Runs weekly.
- Can be manually run on a PR by setting `run-long-verification` label.

File: `long-verification.yml`
3rd party dependencies: None

# Release

Produces CCF reference release artifacts from 5.0.0-rc0 onwards, for all languages and platforms. Triggered on tags matching `ccf-[567].\*`, and manually with an optional dry run. The output of a non-dry-run job is a draft release, which needs to be published manually. Publishing triggers the downstream jobs listed below.

File: `release.yml`
3rd party dependencies: None

# Release Attestation

Generate signed build provenance attestations for release artifacts. Triggered on release publishing.

File: `release-attestation.yml`
3rd party dependencies: None

# NPM

Publishes ccf-app TS package from a GitHub release to NPM. Triggered on release publishing.

File: `npm.yml`
3rd party dependencies: None

# PyPI

Publishes ccf Python package from a GitHub release to PyPI. Triggered on release publishing.

File: `pypi.yml`
3rd party dependencies:

- `pypa/gh-action-pypi-publish@v1.14.0`

# Documentation

Builds and publishes documentation to GitHub Pages. Triggered on pushes to main, and manually. Note that special permissions (Settings > Environment) are configured.

File: `doc.yml`
3rd party dependencies: None

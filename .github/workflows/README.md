Documents the various GitHub Actions workflows, the role they fulfill and 3rd party (i.e. outside of https://github.com/actions/) dependencies if any.

# Shared actions

## Azure Linux CI dependencies

The local composite action in `.github/actions/install-ci-dependencies/action.yml` installs Azure Linux 3 and 4 CI dependencies and caches downloaded RPM and npm packages. Cache keys separate runner architectures, hash the relevant dependency inputs, and include the date of the most recent Sunday at midnight UTC. The RPM key also separates package managers, while the npm key separates jobs so each job can save the packages it downloads. The weekly date makes GitHub Actions create refreshed immutable caches each week.

At a weekly rollover, restore keys first reuse the latest cache for the same dependency inputs and then fall back to a compatible cache for the same architecture. The package managers refresh registry metadata and download only missing or updated packages. `actions/cache` saves each populated directory automatically after a successful job when the exact weekly key was not restored.

The action also assigns uv a writable cache directory outside `/github/home/.cache`, because some tests clear that directory. A weekly cache persists uv's content-addressed package cache, keyed on the pinned uv installer, `python/pyproject.toml`, and the `python-requirements` input, which each workflow sets to the requirements files it installs so unrelated jobs do not invalidate each other's cache; jobs that do not install Python packages disable this cache entirely with `cache-python-packages: false`. CI dependency setup uses `uv pip` so cached packages remain reusable, with workflows configuring the package index through `UV_INDEX_URL`. Pip is not used for package installation because the PyPI proxy redirects artifacts to short-lived URLs that pip cannot reuse across jobs.

# Maintained

## Bencher

Builds and runs CCF performance tests, both end to end and micro-benchmarks. Results are stored as artifacts and summarized in the workflow run against an EWMA baseline with a seven-run half-life.
Triggered on every commit on `main`, twice daily on week days, and manually, but not on PR builds because the setup required to build from forks is complex and fragile in terms of security, and the increase in pool usage would be substantial.

Tests are run on two different testbeds for comparison: gha-vmss-d16av6-ci (d16av6 VMs) and gha-c-aci-ci (C-ACI with 16 cores and 32Gb RAM).

File: `bencher.yml`
3rd party dependencies: None

## Bencher A/B

Builds and runs CCF performance tests on the PR branch, then renders radar charts comparing up to five recent branch runs against the recent trend on `main`. Two nested shaded blue bands show the shared seven-run-half-life EWMA baseline +/- 1 and +/- 2 standard deviations of the latest `main` runs. Both branch and `main` histories are restored from cumulative perf artifacts, and the orange branch lines progress from the faintest oldest run to the strongest latest run. Triggered on PRs that have the label `bench-ab`.

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

Runs the standard model checking, simulation, trace validation, counterexample, and disaster recovery jobs each week.

File: `ci-verification.yml`
3rd party dependencies: None

# Long Verification

Runs the longer consensus model checking and simulation jobs each week.

File: `long-verification.yml`
3rd party dependencies: None

# TLA Shallow Verification

Runs on pull requests that change `tla/` or `src/consensus/aft/raft.h`.

- Simulates the consistency and consensus specifications on a GitHub-hosted runner. The simulation job has a 10-minute timeout.
- Builds the Raft scenario driver and validates its traces against the consensus specification on a GitHub-hosted runner.

File: `tla-shallow.yml`
3rd party dependencies: None

# Vendored Dependency Verification

Verifies that files under `3rdparty/` match the Git commits or release artifacts
recorded in `cgmanifest.json`. Triggered on pull requests and pushes to `main`
that change vendored sources, the manifest, the verifier, or this workflow. It
can also be run manually.

File: `vendor-verification.yml`
3rd party dependencies: None

# Release

Produces CCF reference release artifacts for all languages and platforms. Triggered on tags matching `ccf-[67].*`, and manually with an optional dry run. The output of a non-dry-run job is a draft release, which needs to be published manually. Publishing triggers the downstream jobs listed below.

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

Documents the various GitHub Actions workflows, the role they fulfill and 3rd party (i.e. outside of https://github.com/actions/) dependencies if any.

# Maintained

## Bencher

Builds and runs CCF performance tests, both end to end and micro-benchmarks. Results are posted to bencher.dev, and [plotted to make regressions obvious](https://bencher.dev/console/projects/ccf/plots).
Triggered on every commit on `main`, but not on PR builds because the setup required to build from forks is complex and fragile in terms of security, and the increase in pool usage would be substantial.

Tests are run and published on two different testbeds for comparison: gha-vmss-d16av5-ci (d16ads_v5 VMs) and gha-c-aci-ci (C-ACI with 16 cores and 32Gb RAM), and are labeled accordingly in the bencher UI.

File: `bencher.yml`
3rd party dependencies:

- `bencherdev/bencher@main`

## Bencher A/B

Builds and runs CCF performance tests, and perform a comparison to main. Triggered on PRs that have the label `bench-ab`.

File: `bencher-ab.yml`
3rd party dependencies:

- `bencherdev/bencher@main`

# Continuous Integration

Main continuous integration job. Builds CCF for all target platforms, runs unit, end to end and partition tests. Run on every commit, including PRs from forks, gates merging. Also runs once a week, regardless of commits.

File: `ci.yml`
3rd party dependencies: None

# Long Tests

Secondary continuous integration job. Runs more expensive, longer tests, such as tests against ASAN and TSAN builds, extended fuzzing etc.

- Runs daily on week days.
- Can be manually run on a PR by setting `run-long-test` label, or via workflow dispatch.

File: `long-test.yml`
3rd party dependencies: None

# CodeQL analysis

Builds CCF with CodeQL, and runs the security-extended checks. Triggered on PRs that affect ".github/workflows/codeql-analysis.yml", and once a week on main.

File: `codeql-analysis.yml`
3rd party dependencies:

- `github/codeql-action/init@v3`
- `github/codeql-action/analyze@v3`

# Continuous Verification

Runs quick verification jobs: trace validation, simulation and short model checking configurations. Triggered on PRs that affect tla/ or src/consensus and weekly on main.

File: `ci-verification.yml`
3rd party dependencies: None

# Long Verification

Runs more expensive verification jobs, such as model checking with reconfiguration.

- Runs weekly.
- Can be manually run on a PR by setting `run-long-verification` label.

File: `long-verification.yml`
3rd party dependencies: None

# Release

Produces CCF reference release artefacts from 5.0.0-rc0 onwards, for all languages and platforms. Triggered on tags matching `ccf-[56].\*`. The output of the job is a draft release, which needs to be published manually. Publishing triggers the downstream jobs listed below.

File: `release.yml`
3rd party dependencies: None

# Release Attestation

Generate signed build provenance attestations for release artifacts. Triggered by release creation.

File: `release-attestation.yml`
3rd party dependencies: None

# NPM

Publishes ccf-app TS package from a GitHub release to NPM. Triggered on release publishing.

File: `npm.yml`
3rd party dependencies: None

# PyPI

Publishes ccf Python package from a GitHub release to PyPI. Triggered on release publishing.

File: `pypi.yml`
3rd party dependencies: None

# Documentation

Builds and publishes documentation to GitHub Pages. Triggered on pushes to main, and manually. Note that special permissions (Settings > Environment) are configured.

File: `doc.yml`
3rd party dependencies: None

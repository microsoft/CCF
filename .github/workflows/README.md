Documents the various GitHub Actions workflows, the role they fulfil and 3rd party dependencies if any.

# Backport

Attempts to auto-open backport PRs from main to LTS branch(es) whenever possible. This works well in the absence of conflicts, typically early on during the life of an LTS, and less well later. The alternatives are running the backport tool manually, or cherry picking commits.
Triggered when the label `auto-backport` is applied to a PR, along with the `X.*-todo` label to set the target branch.

File: `backport.yml`
3rd party dependencies: `sorenlouv/backport-github-action@main`

# Bencher

Builds and runs CCF performance tests, both end to end and micro-benchmarks. Results are posted to bencher.dev, and [plotted to make regressions obvious](https://bencher.dev/console/projects/ccf/plots).
Triggered on every commit on `main`, but not on PR builds because the setup required to build from forks is complex and fragile in terms of security, and the increase in pool usage would be substantial.

File: `bencher.yml`
3rd party dependencies: `bencherdev/bencher@main`

# CI Containers GHCR

Produces the build images used by nearly all other actions, particularly CI and release from 5.0.0-rc0 onwards. Complete images are attested and published to GHCR.
Triggered on label creation (`build/*`).

File: `ci-containers-ghcr.yml`
3rd party dependencies:

- `docker/login-action@v3`
- `docker/metadata-action@v5`
- `docker/build-push-action@v6`

# CI

Main continuous integration job. Builds CCF for all target platforms, runs unit, end to end and partition tests Virtual. Run on every commit, including PRs from forks, gates merging. Also runs once a week, regardless of commits.

File: `ci.yml`
3rd party dependencies: None

# CodeQL analysis

Builds CCF with CodeQL, and runs the security-extended checks. Triggered on PRs that affect ".github/workflows/codeql-analysis.yml", and once a week on main.

File: `codeql-analysis.yml`
3rd party dependencies: None

# Verification

Runs all existing TLA+ jobs. Triggered on PRs that affect tla/ or src/consensus and weekly on main.

File: tlaplus.yml
3rd party dependencies: None

# Release

Produces CCF release artefacts from 5.0.0-rc0 onwards, for all languages and platforms. Triggered on tags matching "ccf-5.\*". The output of the job is a draft release, which needs to be published manually. Publishing triggers the downstream jobs listed below.

File: `release.yml`
3rd party dependencies: None

# Containers GHCR

Produces reference release images from 5.0.0-rc0 onwards. Complete images are attested and published to GHCR. Triggered on release publishing.

File: `containers-ghcr.yml`
3rd party dependencies:

- `docker/login-action@v3`
- `docker/metadata-action@v5`
- `docker/build-push-action@v6`

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

# Deprecated

The following pipelines are still here to support 4.x, but will be removed when it reaches EOL.

## CI containers ACR/MCR

File: `ci-containers.yml`

## Release containers ACR/MCR

File: `containers.yml`

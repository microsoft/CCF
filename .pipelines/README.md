# OneBranch release pipelines

Queue these pipelines manually from a `ccf-*` tag after the corresponding GitHub Release is reviewed and published.
Authorize each pipeline to use the existing Azure DevOps Library variable group `ccf-esrp-pypi` for ESRP settings.
Confirm that the shared ESRP registration and publisher have access to each package's registry.
Owners and approvers must be different people.
Published package versions cannot be overwritten.

## PyPI

`pypi.official.yml` builds and publishes the `ccf` wheel through ESRP.
The version is derived from the tag without a version-bump commit, for example `ccf-8.0.0-dev10` becomes `8.0.0.dev10`.
The build validates wheel metadata and installation using `https://packagefeedproxy.microsoft.io/pypi/simple/`.
GitHub Actions does not build, publish, or attest Python wheels.

## npm

`npm.official.yml` builds `@microsoft/ccf-app` with Node.js 24 and `npm pack`, which compiles the TypeScript package.
The package version matches the tag without the `ccf-` prefix; stable releases use the `latest` dist-tag and prereleases use `dev`.
Tests run in CI, not in this publishing pipeline.
The `publish` parameter defaults to `false` (build only); set it to `true` to publish through ESRP.
The GitHub Actions npm publisher remains unchanged; do not publish the same version through both pipelines.

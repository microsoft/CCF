# OneBranch release pipeline

## PyPI

`pypi.official.yml` publishes the `ccf` wheel through OneBranch and ESRP. After
the corresponding GitHub Release is reviewed and published, the pipeline is
manually queued from its `ccf-*` tag. It builds the wheel from that tag,
validates its metadata, installs it in a clean environment, and rejects a
version that already exists on PyPI.

The Azure DevOps pipeline must reference `/.pipelines/pypi.official.yml` and
have access to an Azure DevOps Library variable group named `ccf-esrp-pypi`
containing:

- `ESRP_SERVICE_CONNECTION`
- `ESRP_KEY_VAULT_NAME`
- `ESRP_SIGN_CERT_NAME`
- `ESRP_AUTH_CERT_NAME`
- `ESRP_CLIENT_ID`
- `ESRP_OWNERS`
- `ESRP_APPROVERS`
- `ESRP_MAIN_PUBLISHER`
- `ESRP_DOMAIN_TENANT_ID`
- `GITHUB_ATTESTATION_TOKEN` (secret)

The service connection, Key Vault, certificates, client registration, owners,
and approvers must belong to the CCF ESRP PyPI registration. Owners and
approvers must be different people.

This pipeline is the only Python package publisher. GitHub Actions no longer
builds, attaches, or publishes Python wheels as part of the main CCF release.
Release-build tests use the latest package already released on PyPI; normal
development and CI tests continue to use the local package.

After ESRP confirms publication, a separate Linux job dispatches
`.github/workflows/python-package-attestation.yml` on the release tag. This
avoids running custom scripts in the governed ESRP release job. `GITHUB_ATTESTATION_TOKEN` must
be a GitHub credential authorized to dispatch workflows in `microsoft/CCF`,
with repository-scoped Actions write permission. Store it as a secret in the
variable group and authorize the pipeline to use it. The attestation workflow
must be merged to `main` and included in the release tag before enabling this
stage.

The build supplies its wheel SHA-256 digest and package version as stage outputs.
The attestation workflow checks the release tag and source commit, then verifies
that the PyPI wheel matches the build's digest and package metadata. It uploads
`python-package.attestation.sigstore.json` to the corresponding GitHub release,
separately from the non-Python release attestation. This is a GitHub attestation
of the verified published wheel, not build-time OneBranch provenance.

OneBranch success confirms that the GitHub attestation workflow was dispatched;
check that workflow's result to confirm attestation completed. If publication
succeeded but dispatch or attestation failed, retry only the attestation stage
or workflow using the original build inputs and selecting the release tag,
not a branch, as the workflow ref. Do not republish the wheel or move
the tag. If publication itself was incomplete, skip that version and publish a
new version.

Before publication, the pipeline verifies that:

- It was queued from a `ccf-*` tag.
- The tag version matches `python/pyproject.toml`.
- Exactly one `ccf` wheel is built.
- The wheel name and version match the tag.
- The wheel installs in a clean environment.
- The version does not already exist on PyPI.

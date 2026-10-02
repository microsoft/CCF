# OneBranch pipelines

## Pull request and official builds

`pullrequest.yml` and `official.yml` share the build and test stages in
`common.yml`. Pull request builds use the OneBranch non-official template.
Official builds run for `main` and `ccf-*` tags with the OneBranch official
template. Release tags additionally produce the RPM, Python wheel, NPM package,
SBOM, reports, release notes, and sample binaries under the OneBranch output
directory.

Both pipelines require a custom Azure DevOps pool named `ado-ccf-pool`. Its
agents must:

- Run Azure Linux 3.
- Permit package installation as root.
- Provide the `NET_ADMIN`, `NET_RAW`, and `SYS_PTRACE` capabilities used by
  CCF tests.
- Permit the IPv6 sysctls used by the existing CCF CI containers.
- Provide Docker, Git, and `jq` on the host for release and reproducibility
  builds.
- Have sufficient CPU, memory, and disk capacity for a complete CCF build and
  test run.

They also require an `ado-ccf-snp-pool` whose agents run on SEV-SNP Genoa
hardware and provide the same environment and device access as the existing
`gha-aci-genoa` GitHub Actions pool. The SNP workload runs directly on the host,
not in the OneBranch build container.

The pull request pipeline must be configured as an Azure DevOps branch policy
for the GitHub repository. The official pipeline triggers for every commit to
`main` and every `ccf-*` tag.

CCF does not currently define a production container image, so these pipelines
do not publish to ACR. Add an ACR stage only after a production image and its
registry, service connections, and promotion policy are defined.

## PyPI

`pypi.official.yml` publishes the `ccf` wheel through OneBranch and ESRP. The
pipeline is manually queued from a `ccf-*` tag. It builds the wheel from that
tag, validates its metadata, installs it in a clean environment, and rejects a
version that already exists on PyPI.

The Azure DevOps pipeline must reference `/.pipelines/pypi.official.yml` and
have access to a variable group named `ccf-esrp-pypi` containing:

- `ESRP_SERVICE_CONNECTION`
- `ESRP_KEY_VAULT_NAME`
- `ESRP_SIGN_CERT_NAME`
- `ESRP_AUTH_CERT_NAME`
- `ESRP_CLIENT_ID`
- `ESRP_OWNERS`
- `ESRP_APPROVERS`
- `ESRP_MAIN_PUBLISHER`
- `ESRP_DOMAIN_TENANT_ID`

The service connection, Key Vault, certificates, client registration, owners,
and approvers must belong to the CCF ESRP PyPI registration. Owners and
approvers must be different people.

The existing GitHub Actions workflows remain active while OneBranch runs are
validated. Disable the old publishers only after their OneBranch replacements
have completed a production release successfully.

Before publication, the pipeline verifies that:

- It was queued from a `ccf-*` tag.
- The tag version matches `python/pyproject.toml`.
- Exactly one `ccf` wheel is built.
- The wheel name and version match the tag.
- The wheel installs in a clean environment.
- The version does not already exist on PyPI.

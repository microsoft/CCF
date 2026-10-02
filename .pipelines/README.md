# OneBranch release pipeline

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

The existing GitHub Actions PyPI workflow remains active while this pipeline is
validated. Disable the old publisher only after the OneBranch replacement has
completed a production release successfully.

Before publication, the pipeline verifies that:

- It was queued from a `ccf-*` tag.
- The tag version matches `python/pyproject.toml`.
- Exactly one `ccf` wheel is built.
- The wheel name and version match the tag.
- The wheel installs in a clean environment.
- The version does not already exist on PyPI.

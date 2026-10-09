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

The service connection, Key Vault, certificates, client registration, owners,
and approvers must belong to the CCF ESRP PyPI registration. Owners and
approvers must be different people.

The existing GitHub Actions PyPI workflow remains active during non-production
validation. Before enabling this pipeline for production, disable the GitHub
Actions PyPI workflow so only one publisher can process a release. If a release
attempt publishes the wheel but another release artifact fails, do not move or
recreate that tag; skip the incomplete version and publish a new version.

Before publication, the pipeline verifies that:

- It was queued from a `ccf-*` tag.
- The tag version matches `python/pyproject.toml`.
- Exactly one `ccf` wheel is built.
- The wheel name and version match the tag.
- The wheel installs in a clean environment.
- The version does not already exist on PyPI.

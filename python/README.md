# CCF Python

Suite of Python tools for the Confidential Consortium Framework (CCF).

For more information, please find the CCF documentation at https://microsoft.github.io/CCF.

Package sources are available at https://github.com/microsoft/CCF/tree/main/python.

Run `scripts/python-types-checks.sh` from the repository root to check the SDK, tutorial, and SDK tests with Pyright.
The configuration in `python/pyproject.toml` checks against Python 3.12 and resolves SDK imports from the local sources.
Every package module and the tutorial use Pyright's strict checks, including ledger parsing and verification.
The SDK tests retain ordinary checking.
New package modules are checked strictly by default; do not disable individual diagnostics to extend coverage.

The signature verifiers shared across package modules are available as `ccf.signatures.verify_all_root_signatures` and `ccf.signatures.verify_cose_root_signature_with_key`.
Their former underscore-prefixed names remain aliases for compatibility.

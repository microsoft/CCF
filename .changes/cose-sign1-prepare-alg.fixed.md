`ccf_cose_sign1_prepare` and `ccf.cose.create_cose_sign1_prepare` again return the `alg` as a JSON Web Algorithm name such as `"ES384"`, as Azure Key Vault expects, and hash the message with the algorithm of the signing key rather than that of the certificate's own signature.
See [COSE Signing](doc/governance/hsm_keys.rst#cose-signing).

Insecure Virtual
================

.. warning:: The Insecure Virtual mode does not provide any security guarantees and should be used for development purposes only.

How to use the Insecure Virtual Platform
----------------------------------------

The insecure virtual platform is a default fallback option if SEV-SNP is not supported on the machine of choice.

There's a "virtual" (fake) attestation provided by nodes, which exists to unify some of the code paths, but has no real security properties.

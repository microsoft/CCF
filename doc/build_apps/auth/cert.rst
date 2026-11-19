Certificate Authentication
==========================

User identities in CCF can be legacy X.509 certificates or certificate-free ``did:key`` public keys.
They can be added or removed via governance proposals, which are subject to the consortium constitution rules (see :ref:`governance/open_network:Adding Users`).

Requests sent by users can be authenticated one of two ways:

- via the TLS handshake, in which a client uses the user private key to prove its identity (e.g. using the ``--key`` and ``--cert`` argument to ``curl``)
- by :ref:`use_apps/issue_commands:COSE Sign1` signing the request contents with the user private key, when the endpoint uses :cpp:var:`ccf::user_cose_sign1_auth_policy`.

By default, the user ID is the SHA-256 fingerprint of the registered certificate.
Users enrolled with ``"did_key": "<did:key>"`` are identified by their public key and need no certificate for COSE authentication.
See :ref:`architecture/cryptography:Identity IDs` for how these users authenticate with a TLS client certificate, and for the supported keys.

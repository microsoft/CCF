Certificate Authentication
==========================

User identities in CCF are X.509 certificates. They can be added or removed via governance proposals, which are subject to the consortium constitution rules (see :ref:`governance/open_network:Adding Users`).

Requests sent by users can be authenticated one of two ways:

- via the TLS handshake, in which a client uses the user private key to prove its identity (e.g. using the ``--key`` and ``--cert`` argument to ``curl``)
- by :ref:`use_apps/issue_commands:Signing` the request contents with the user private key, following the scheme described `here <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_.

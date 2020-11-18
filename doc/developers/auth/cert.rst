Certificate Authentication
==========================

User identities in CCF are X.509 certificates. They can be added or removed via governance proposals, which are subject to the consortium constitution rules (see :ref:`members/open_network:Adding Users`).

Requests emitted by users can be authenticated one of two ways:

- via the TLS handshake, in which a client uses the user private key to prove its identity (e.g. using the ``--key`` and ``--cert`` argument to ``curl``)
- by signing the request contents with the user private key, following the scheme described `here <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_

This certificate-based authentication can be disabled for a specific application endpoint, via the :cpp:func:`ccf::EndpointRegistry::Endpoint::set_require_client_identity()`.
If certificate authentication is disabled, the application should authenticate and authorise users based on other mechanisms, such as :doc:`/developers/auth/jwt`.

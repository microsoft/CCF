User Authentication
===================

Each endpoint in CCF declares how callers should be authenticated, listing potentially multiple policies.
Each request to this endpoint will first be checked by these policies in the order they are specified, and the handler will only be invoked if at least one of these policies accepts the request. The identity found by this check can then be accessed by the handler to make further authorization decisions. CCF provides some authentication policies by default, and additional custom policies can be defined in :ref:`C++ <build_apps/example_cpp:Authentication>`.

.. note:: The experimental :doc:`Rust SDK <../rust_api>` supports only ``Auth::UserCert`` and ``Auth::None``, and does not give handlers the caller's identity.

CCF provides support for two common user authentication schemes: certificate authentication, described below, and :doc:`JSON Web Token (JWT) authentication <jwt>`.

.. toctree::
  :maxdepth: 1

  jwt

Certificate Authentication
--------------------------

User identities in CCF are X.509 certificates.
They can be added or removed via governance proposals, which are subject to the consortium constitution rules (see :ref:`governance/open_network:Adding Users`).

Requests sent by users can be authenticated one of two ways:

- via the TLS handshake, in which a client uses the user private key to prove its identity (e.g. using the ``--key`` and ``--cert`` argument to ``curl``)
- by :ref:`use_apps/issue_commands:COSE Sign1` signing the request contents with the user private key, when the endpoint uses :cpp:var:`ccf::user_cose_sign1_auth_policy`.

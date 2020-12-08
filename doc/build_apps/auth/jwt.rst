JWT Authentication
==================

JWT (`JSON Web Token <https://tools.ietf.org/html/rfc7519>`_) bearer authentication allows to use an external identity provider (IdP) such as the `Microsoft Identity Platform <https://aka.ms/IdentityPlatform>`_ for user authentication in CCF.

Once the user has acquired a token from an IdP supported by the app, they can include it in HTTP requests in the ``Authorization`` header as `bearer token <https://tools.ietf.org/html/rfc6750>`_.
The CCF app validates the token and can then use the user identity and other claims embedded in the token.

CCF provides support for managing public token signing keys required for validating tokens.
In the future, CCF will support validating token signatures natively (currently the responsibility of apps).

Setting up a token issuer with manual key refresh
-------------------------------------------------

Before adding public token signing keys to a running CCF network, the IdP has to be stored as token issuer with a ``set_jwt_issuer`` proposal:

.. code-block:: bash

    $ cat issuer.json
    {
      "issuer": "my-issuer",
      "auto_refresh": false
    }
    $ python -m ccf.proposal_generator set_jwt_issuer issuer.json

The ``issuer`` field is an arbitrary identifier and should be used during token validation to differentiate between multiple issuers.

Note that ``issuer.json`` has some additional optional fields for more advanced scenarios.
See :ref:`build_apps/auth/jwt:Advanced issuer configuration` for details.

After this proposal is accepted, signing keys for an issuer can be updated with a ``set_jwt_public_signing_keys`` proposal:

.. code-block:: bash

    $ ISSUER="my-issuer"
    $ python -m ccf.proposal_generator set_jwt_public_signing_keys $ISSUER jwks.json

``jwks.json`` contains the signing keys as JWKS (`JSON Web Key Set <https://tools.ietf.org/html/rfc7517>`_) document. 

Setting up a token issuer with automatic key refresh
----------------------------------------------------

Most IdPs follow the OpenID Connect Discovery specification and publish their public token signing keys at a well-known location.
In such cases, token issuers in CCF can be configured to automatically refresh their keys.

The following extra conditions must be true compared to setting up an issuer with manual key refresh:

- The ``issuer`` must be an OpenID Connect issuer URL, for example ``https://login.microsoftonline.com/common/v2.0``. During auto-refresh, the keys are fetched from that URL by appending ``/.well-known/openid-configuration``.
- A CA certificate for the issuer URL must be stored so that the TLS connection to the IdP can be validated during key refresh.

The CA certificate is stored with a ``set_ca_cert`` proposal:

.. code-block:: bash

    $ python -m ccf.proposal_generator set_ca_cert jwt_ms cacert.pem

Now the issuer can be created with auto-refresh enabled:

.. code-block:: bash

    $ cat issuer.json
    {
      "issuer": "https://login.microsoftonline.com/common/v2.0",
      "auto_refresh": true,
      "ca_cert_name": "jwt_ms"
    }
    $ python -m ccf.proposal_generator set_jwt_issuer issuer.json

.. note::

    The key refresh interval is set via the ``--jwt-key-refresh-interval-s <seconds>`` CLI option for ``cchost``, where the default is 30 min.

Removing a token issuer
-----------------------

If an issuer should not be used anymore, then a ``remove_jwt_issuer`` proposal can be used to remove both the issuer and its signing keys:

.. code-block:: bash

    $ ISSUER="https://login.microsoftonline.com/common/v2.0"
    $ python -m ccf.proposal_generator remove_jwt_issuer $ISSUER

Validating tokens
-----------------

Validating a token means checking its format, signature, and IdP- and app-specific claims.
See `samples/apps/forum/src/authentication.ts <https://github.com/microsoft/CCF/blob/master/samples/apps/forum/src/authentication.ts>`_ for an example on how to do this in TypeScript.

Token signing keys are stored in the ``public:ccf.gov.jwt_public_signing_keys`` kv map where the key is the key ID and the value the DER-encoded X.509 certificate. The key ID matches the ``kid`` field in the token header and can be used to retrieve the matching certificate for validation.

If an application uses multiple token issuers, then the ``public:ccf.gov.jwt_public_signing_key_issuer`` kv map which maps key IDs to issuers can be used to determine the issuer that a key belongs to.

Advanced issuer configuration
-----------------------------

CCF has special support for IdPs that issue tokens within SGX enclaves, for example MAA (`Microsoft Azure Attestation <https://docs.microsoft.com/en-us/azure/attestation/>`_).
The goal is to validate that a token has indeed been issued from an SGX enclave that has certain properties.
CCF supports the approach taken by MAA where the token signing key and certificate are generated inside the enclave and the certificate embeds evidence from the enclave platform in an X.509 extension (see Open Enclave's  `oe_get_attestation_certificate_with_evidence() <https://openenclave.io/apidocs/v0.12/attester_8h_a2d7a05a906935c74a089d3b1240fad64.html#a2d7a05a906935c74a089d3b1240fad64>`_ for details).
In this model it is sufficient to validate the evidence of the signing certificates when storing them in CCF.
After the signing certificates have been stored, token validation follows the same methods as described in earlier sections.

CCF validates embedded SGX evidence if a key policy is given in the issuer metadata:

.. code-block:: bash

    $ cat issuer.json
    {
      "issuer": "https://shareduks.uks.attest.azure.net",
      "key_filter": "sgx",
      "key_policy": {
        "sgx_claims": {
          "signer_id": "5e5410aaf99a32e32df2a97d579e65f8310f274816ec4f34cedeeb1be410a526",
          "attributes": "0300000000000000"
        }
      }
    }
    $ python -m ccf.proposal_generator set_jwt_issuer issuer.json

All claims contained in ``key_policy.sgx_claims`` must be identical to the ones embedded in the certificate.
Any attempt to add a certificate with mismatching claims in a ``set_jwt_public_signing_keys`` proposal for that issuer would result in failure.

.. note::

    See Open Enclave's `oe_verify_evidence() <https://openenclave.io/apidocs/v0.12/verifier_8h_a5ad1a6314d2fe5b3470cb3a25c4c39df.html#a5ad1a6314d2fe5b3470cb3a25c4c39df>`_ for a list of available claim names and their meaning. Note that all claim values must be given hex-encoded.

Some IdPs, like MAA, advertise a mix of SGX and non-SGX signing certificates.
In this case, ``key_filter`` must be set to ``sgx`` such that only those certificates are stored which contain SGX evidence.

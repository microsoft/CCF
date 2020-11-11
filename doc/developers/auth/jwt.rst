JWT Authentication
==================

JWT (`JSON Web Token <https://tools.ietf.org/html/rfc7519>`_) bearer authentication allows to use an external identity provider (IdP) such as the `Microsoft Identity Platform <https://aka.ms/IdentityPlatform>`_ for user authentication in CCF.

Once the user has acquired a token from an IdP supported by the app, they can include it in HTTP requests in the ``Authorization`` header as `bearer token <https://tools.ietf.org/html/rfc6750>`_.
The CCF app validates the token and can then use the user identity and other claims embedded in the token.

CCF provides support for storing and retrieving public token signing keys required for validating tokens.
In the future, CCF will support validating token signatures (currently the responsibility of apps) and automatically refreshing token signing keys from OpenID Provider Configuration endpoints.

Storing public token signing keys
---------------------------------

IdPs sign tokens with private keys that are periodically updated.
Corresponding public keys in the form of certificates are needed to validate the signature of a token and are typically published by IdPs at a well-known location in JWKS (`JSON Web Key Set <https://tools.ietf.org/html/rfc7517>`_) format.

.. note::

    Most IdPs support the OpenID Connect Discovery specification which defines how to discover the location to the  certificates.
    In short, the IdP issuer URL, for example ``https://login.microsoftonline.com/common/v2.0``, is suffixed with ``/.well-known/openid-configuration`` and the ``jwks_uri`` field of the JSON document at that URL is the location of the JWKS     document containing the certificates currently in use. In this example, it would be `<https://login.microsoftonline.com/    common/discovery/v2.0/keys>`_.

Before adding public token signing keys to a running CCF network, the IdP has to be stored as token issuer with a ``set_jwt_issuer`` proposal:

.. code-block:: bash

    $ cat issuer.json
    {
      "issuer": "https://login.microsoftonline.com/common/v2.0"
    }
    $ python -m ccf.proposal_generator set_jwt_issuer issuer.json

Note that ``issuer.json`` has some additional optional fields for more advanced scenarios.
See :ref:`developers/auth/jwt:Advanced issuer configuration` for details.

After this proposal is accepted, signing keys for an issuer can be updated with a ``set_jwt_public_signing_keys`` proposal:

.. code-block:: bash

    $ curl "https://login.microjsononline.com/common/discovery/v2.0/keys" -o jwks.json
    $ ISSUER="https://login.microsoftonline.com/common/v2.0"
    $ python -m ccf.proposal_generator set_jwt_public_signing_keys $ISSUER jwks.json

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

Example using Microsoft Identity Platform
-----------------------------------------

The `Forum sample app <https://github.com/microsoft/CCF/blob/master/samples/apps/forum>`_ of CCF uses the `Microsoft Identity Platform <https://aka.ms/IdentityPlatform>`_ for user authentication.
In this sample, users submit opinions for polls without other users seeing their opinions.
After a certain number of opinions have been submitted, aggregate statistics can be retrieved.

To get started, `register an application <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app>`_ with the Microsoft Identity Platform.
After registering the app, navigate to "Expose an API" and create a scope named ``Polls.Access``, allowing "Admins and users" to consent.
The name of the scope is used in the JavaScript code of the website client.
Under "Authentication", make sure a "Single-page application" is added with a redirect URL that matches the website.
In the Forum sample the redirect URL is ``https://.../app/site``, and particularly during development it is convenient to add a local URL as well: ``https://127.0.0.1:8000/app/site``.

.. note::

    The Forum sample is technically a combination of a `web API application <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-expose-web-apis>`_ (the CCF app) and a `browser client application <https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-configure-app-access-web-apis>`_ (the website).
    The latter is also called a single-page application in Microsoft terms.
    For simplicity and because both applications are considered public it is sufficient to register only a single application which will represent both the server and the client.

Open `samples/apps/forum/src/authentication.ts <https://github.com/microsoft/CCF/blob/master/samples/apps/forum/src/authentication.ts>`_ and replace the app ID with the one registered earlier.
This file is responsible for validating incoming JWTs and extracting a user id for associating opinions to users.

The Forum sample can now be run in a local sandbox with:

.. code-block:: bash

    $ cd samples/apps/forum
    $ npm install
    $ npm start
    
Navigate to `<https://127.0.0.1:8000/app/site>`_ and click the Login button.
You will be redirected to the Microsoft Identity Platform for authentication and back to the Forum sample.
After logging in, polls can be created and opinions submitted.

Note that aggregated opinion data is only returned after reaching a certain threshold.
To simulate multiple different users submitting opinions, the `start script <https://github.com/microsoft/CCF/blob/master/samples/apps/forum/test/start.ts>`_ adds an additional fake JWT issuer based on a locally generated private key and certificate.
Run the following scripts to submit opinions of fake users using the fake issuer:

.. code-block:: bash

    $ python3.8 test/demo/generate-opinions.py test/demo/polls.csv 9
    $ npm run ts test/demo/generate-jwts.ts . 9
    $ npm run ts test/demo/submit-opinions.ts .

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

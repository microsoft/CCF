JWT Authentication
==================

JWT (`JSON Web Token <https://tools.ietf.org/html/rfc7519>`_) bearer authentication allows to use an external identity provider (IdP) such as the `Microsoft Identity Platform <https://aka.ms/IdentityPlatform>`_ for user authentication in CCF.

Once the user has acquired a token from an IdP supported by the app, they can include it in HTTP requests in the ``Authorization`` header as `bearer token <https://tools.ietf.org/html/rfc6750>`_.
The CCF app validates the token and can then use the user identity and other claims embedded in the token. Tokens must contain valid Not Before (nbf) and Expiration Time (exp) claims. If these are missing, or the current time (set on the executing node by the untrusted host) is outside this range, then CCF will return an error and not allow this token to be used for authentication.

CCF provides support for managing public token signing keys and using those to validate tokens.

Setting up a token issuer with manual key refresh
-------------------------------------------------

Before adding public token signing keys to a running CCF network, the IdP has to be stored as token issuer with a ``set_jwt_issuer`` proposal:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_jwt_issuer",
          "args": {
            "issuer": "my_issuer",
            "key_filter": "all",
            "auto_refresh": false
          }
        }
      ]
    }

The ``issuer`` field is an arbitrary identifier and should be used during token validation to differentiate between multiple issuers.

Note that this action takes some additional optional args for more advanced scenarios.
See :ref:`build_apps/auth/jwt:Advanced issuer configuration` for details.

After this proposal is accepted, signing keys for an issuer can be updated with a ``set_jwt_public_signing_keys`` proposal:

.. code-block:: bash

    {
      "actions": [
        {
          "name": "set_jwt_public_signing_keys",
          "args": {
            "issuer": "my_issuer",
            "jwks": {
              "keys": [
                {
                  "kty": "RSA",
                  "kid": "my_kid",
                  "x5c": [
                    "MIICrDCCAZSgAwIBAgIUcj2cyqhj1U8XzZ0gvV1sF4e4vtowDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UEAwwFZHVtbXkwHhcNMjIwMTEyMTM0MzMzWhcNMjIwMTIyMTM0MzMzWjAQMQ4wDAYDVQQDDAVkdW1teTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK/RrDSau3y4uI0AMKRfeC/aflZ7LfqFeaWOrj3WrDd1lWIJNJfXw4yrjyLq/NxDPF/3Rk4JBA4FPxUuQ2gwiLaZr9/OJjG2e+1sT9Sj243IC4tKvm8ilUtbgx9f9GvyoP5UhnZHa3GQ2MnRpTtzOq2u+XhjrQBfadGEVjUCpbwRaV7vTUr2WZQ/e1HbLFg0vdApP/U2Z/p5LUyRooLIu12mgMFZAd8zYWXsHGx+D4F8DeRpuPDrF5CKOeA2HvhIeYy+kKMhSuE2wBn3lHtTstZfoJoJJuDPwr5F58jlBHBdRL7BtfB2O8jK5iPNb3bZnyAgQ4xJVr/4wUcbeI7SA28CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAXlso7E6vqH0W9w3jMrtIWJiZWZi1O+JQ3TkcVX0qTHHQRSjFyY+wjjL11ERZqz2XnrfQZDQdlpB4g7EXh24lN7QE5XuxN6gfRVDPVrY8+mg5qXBW6yz70Kgt7iuy5QjTOMU3GjqYBjObcXBqp+/p6mU0cTFHSt7xQjK2XI1AdOuxeAtUsko6+pvMwZus2RARzJurSAuWh4mU2ozALmUlAD+looOsvqui4s6CNUUakfSUlDj5drnYOHqqrRXDVonzDCDJgN/ZJubwFkTmZ1Urr5OTR5/WdC9G69RU27eqyRFuWlCafy8+hwyo6sZykDJpa6FBbeXWfm7s8Sj77y0Gdg=="
                  ]
                }
              ]
            }
          }
        }
      ]
    }

The ``"jwks"`` field contains the signing keys as a JWKS (`JSON Web Key Set <https://tools.ietf.org/html/rfc7517>`_) document.

Setting up a token issuer with automatic key refresh
----------------------------------------------------

Most IdPs follow the OpenID Connect Discovery specification and publish their public token signing keys at a well-known location.
In such cases, token issuers in CCF can be configured to automatically refresh their keys.

The following extra conditions must be true compared to setting up an issuer with manual key refresh:

- The ``issuer`` must be an OpenID Connect issuer URL, for example ``https://login.microsoftonline.com/common/v2.0``. During auto-refresh, the keys are fetched from that URL by appending ``/.well-known/openid-configuration``.
- A CA certificate for the issuer URL must be stored so that the TLS connection to the IdP can be validated during key refresh.

The CA certificate is stored with a ``set_ca_cert_bundle`` proposal:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_ca_cert_bundle",
          "args": {
            "name": "jwt_ms",
            "cert_bundle": "-----BEGIN CERTIFICATE-----\nMIICtDCCAZygAwIBAgIUD7xmXLQWbN/q+tuH97Aq2krO0GAwDQYJKoZIhvcNAQEL\nBQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTIyMDExMjEzNDMzNloXDTIyMDEy\nMjEzNDMzNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\nAAOCAQ8AMIIBCgKCAQEAoWXwixcQ0CrZQAD9Ojo0kxKtrsJB0dmxwKGx/JH2VQYh\nYQ9+8zSuXKW7L0dJL3Qf9R7eJvj1w4i/gPHSggsgrp+MbYLos3DK1M3wdATpsn/r\nhVFCuVpq9nVOZQh9Uiq1fbsYBpoJZ+aSpRJrqK8VaQDr/zPVnU72zYSxgEvwll+e\nvw1+erna3nZevf02hGvD1HU2DBEIkyj50yRzfKufGbw70ySxDAxCpkM+Qsw+WD5/\ncI2D8mhMFA7NdPIbB0OWwCOqrFxtwkA2N11nqJlodzFmcdCDE/fyZc2/Fer+C4ol\nhnYBXVqEodlbytmYHIWB3+XbymDrbqPeCvr2I6nK2QIDAQABMA0GCSqGSIb3DQEB\nCwUAA4IBAQBrHD9cUy5mfkelWzJRknaK3BszUWSwOjjXYh0vFTW8ixZUjKfQDpbe\nPEL3aV3IgnBEwFnormhGCLcOatAGLCgZ//FREts8KaNgyrObKyuMLPQi5vf5/ucG\n/68mGwq2hdh0+ysVqcjjLQCTfbPJPUQ5V2hOh79jOy29JdavcBGR4SeRdOgzdcwA\nd9/T8VuoC6tjt2OF7IJ59JOSBWMcxCbr7KyyJjuxykzyjDa/XQs2Egt4WE+ZVUgc\nav1tQB2leiJGbjhswhLMe7NbuOtwcELsILpPo3pbdKEMlRFngj7H80IFurxtdu/M\nN2D/+LkySi6UDM8q6ADSdjG+cnNzSjEo\n-----END CERTIFICATE-----\n"
          }
        }
      ]
    }

Now the issuer can be created with auto-refresh enabled:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_jwt_issuer",
          "args": {
            "issuer": "https://login.microsoftonline.com/common/v2.0",
            "key_filter": "all",
            "ca_cert_bundle_name": "jwt_ms",
            "auto_refresh": true
          }
        }
      ]
    }

.. note::

    The key refresh interval is set via the ``jwt.key_refresh_interval_s`` configuration entry, where the default is 30 min (1800 seconds).

Removing a token issuer
-----------------------

If an issuer should not be used anymore, then a ``remove_jwt_issuer`` proposal can be used to remove both the issuer and its signing keys:

.. code-block:: bash

    {
      "actions": [
        {
          "name": "remove_jwt_issuer",
          "args": {
            "issuer": "https://login.microsoftonline.com/common/v2.0"
          }
        }
      ]
    }

Validating tokens
-----------------

Validating a token means checking its format, signature, and IdP- and app-specific claims. See :ccf_repo:`tests/js-authentication/src/endpoints.js` for an example on how to do this in TypeScript.

Token signing keys are stored in the ``public:ccf.gov.jwt.public_signing_keys`` kv map where the key is the key ID and the value the DER-encoded X.509 certificate. The key ID matches the ``kid`` field in the token header and can be used to retrieve the matching certificate for validation.

If an application uses multiple token issuers, then the ``public:ccf.gov.jwt.public_signing_key_issuer`` kv map which maps key IDs to issuers can be used to determine the issuer that a key belongs to.

Advanced issuer configuration
-----------------------------

CCF has special support for IdPs that issue tokens within SGX enclaves, for example MAA (`Microsoft Azure Attestation <https://docs.microsoft.com/en-us/azure/attestation/>`_).
The goal is to validate that a token has indeed been issued from an SGX enclave that has certain properties.
CCF supports the approach taken by MAA where the token signing key and certificate are generated inside the enclave and the certificate embeds evidence from the enclave platform in an X.509 extension (see Open Enclave's  `oe_get_attestation_certificate_with_evidence() <https://openenclave.io/apidocs/v0.12/attester_8h_a2d7a05a906935c74a089d3b1240fad64.html#a2d7a05a906935c74a089d3b1240fad64>`_ for details).
In this model it is sufficient to validate the evidence of the signing certificates when storing them in CCF.
After the signing certificates have been stored, token validation follows the same methods as described in earlier sections.

CCF validates embedded SGX evidence if a key policy is given in the issuer metadata:

.. code-block:: json

    {
      "actions": [
        {
          "name": "set_jwt_issuer",
          "args": {
            "issuer": "https://shareduks.uks.attest.azure.net",
            "key_filter": "sgx",
            "key_policy": {
              "sgx_claims": {
                "signer_id": "5e5410aaf99a32e32df2a97d579e65f8310f274816ec4f34cedeeb1be410a526",
                "attributes": "0300000000000000"
              }
            },
            "auto_refresh": false
          }
        }
      ]
    }

All claims contained in ``key_policy.sgx_claims`` must be identical to the ones embedded in the certificate.
Any attempt to add a certificate with mismatching claims in a ``set_jwt_public_signing_keys`` proposal for that issuer would result in failure.

.. note::

    See Open Enclave's `oe_verify_evidence() <https://openenclave.io/apidocs/v0.12/verifier_8h_a5ad1a6314d2fe5b3470cb3a25c4c39df.html#a5ad1a6314d2fe5b3470cb3a25c4c39df>`_ for a list of available claim names and their meaning. Note that all claim values must be given hex-encoded.

Some IdPs, like MAA, advertise a mix of SGX and non-SGX signing certificates.
In this case, ``key_filter`` must be set to ``sgx`` such that only those certificates are stored which contain SGX evidence.

Extracting JWT metrics
----------------------

CCF tracks JWT key auto-refresh attempts and successes.
This can be used to identify errors, for example when the number of attempts doesn't match the number of successes.
For each issuer that has auto-refresh enabled, CCF tracks an attempt for each try, and eventually a success, if the update completes.

Operators can query those numbers via the :http:GET:`/node/jwt_metrics` endpoint.

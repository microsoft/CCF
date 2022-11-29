Issuing Commands
================

Clients communicate with CCF using HTTP requests, over TLS.

For example, to record a message at a specific id with the :doc:`C++ sample logging application </build_apps/example>` using curl:

.. code-block:: bash

    $ cat request.json
    {
      "id": 42,
      "msg": "Hello There"
    }

    $ curl https://<ccf-node-address>/app/log/private --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @request.json -H "content-type: application/json" -i
    HTTP/1.1 200 OK
    content-length: 5
    content-type: application/json
    x-ms-ccf-transaction-id: 2.23

    true

The HTTP response some CCF commit information in the headers:

- ``"x-ms-ccf-transaction-id"`` indicates the consensus view, and the unique version at which the request was executed, separated by a ``"."``.

The response body (the JSON value ``true``) indicates that the request was executed successfully. For many RPCs this will be a JSON object with more details about the execution result.

Signing
-------

In some situations CCF requires signed requests, for example for member votes. Two signing schemes are supported as of 3.x.

HTTP Signatures
~~~~~~~~~~~~~~~

An implementation of `IETF HTTP Signatures draft RFC <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-08>`_ , but
supports `ecdsa-sha256` as well as `hs2019` signing algorithms as described in the later `draft 12 <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12>`_.
We provide a wrapper script (``scurl.sh``) around ``curl`` to submit signed requests from the command line.
This passes most args verbatim to ``curl``, but expects additional ``--signing-cert`` and ``--signing-key`` args which specify the identity used to sign the request.
These are distinct from the ``--cert`` and ``--key`` args which are passed to ``curl`` as the client TLS identity, and may specify a different identity.

CCF identifies the signing identity for a request via the SHA-256 digest of its certificate, represented as a hex string.
That value must be set in the ``keyId`` field of the ``Authorization`` HTTP header for a signed request.

These commands can also be signed and transmitted by external libraries.
For example, the CCF test infrastructure uses a custom authentication provider for `Python HTTPX <https://www.python-httpx.org/>`_.

.. note:: This signing mechanism is still supported for the duration of 3.x, but will be dropped in 4.0 because it is coupled to HTTP, and has not reached adoption as a standard or in libraries.

COSE Sign1
~~~~~~~~~~

Since 3.0, CCF also accepts signed requests in `COSE Sign1 <https://www.rfc-editor.org/rfc/rfc8152#section-4.2>`_ format.

CCF identifies the signing identity for a request via the SHA-256 digest of its certificate, represented as a hex string.
That value must be set in the ``kid`` protected header. Additional protected headers may be necessary, for example governance endpoints
require setting ``ccf.gov.msg.type``, and optionally ``ccf.gov.msg.proposal_id`` on the message types where it applies.

A signing script (``ccf_cose_sign1``) is provided as part of the `ccf Python package <https://pypi.org/project/ccf/>`_. The output can be piped directly into curl, or any other HTTP client.

Commands can also be signed using the pycose library, and sent with any standard HTTP library such as `Python HTTPX <https://www.python-httpx.org/>`_.
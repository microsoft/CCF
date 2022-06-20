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

In some situations CCF requires signed requests, for example for member votes.
The signing scheme is compatible with the `IETF HTTP Signatures draft RFC <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-08>`_,
and supports the `ecdsa-sha256` as well as `hs2019` signing algorithms as described in the later `draft 12 <https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12>`_
We provide a wrapper script (``scurl.sh``) around ``curl`` to submit signed requests from the command line.
This passes most args verbatim to ``curl``, but expects additional ``--signing-cert`` and ``--signing-key`` args which specify the identity used to sign the request.
These are distinct from the ``--cert`` and ``--key`` args which are passed to ``curl`` as the client TLS identity, and may specify a different identity.

CCF identifies the signing identity for a request via the SHA-256 digest of its certificate (DER encoded), represented as a hex string.
That value must be set in the ``keyId`` field of the ``Authorization`` HTTP header for a signed request.

These commands can also be signed and transmitted by external libraries.
For example, the CCF test infrastructure uses `an auth plugin <https://pypi.org/project/requests-http-signature/>`_ for `Python Requests <https://requests.readthedocs.io/en/stable/>`_.

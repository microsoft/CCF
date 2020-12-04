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

    $ curl https://<ccf-node-address>/app/log/private --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @request.json -H "content-type: application/json" -i
    HTTP/1.1 200 OK
    content-length: 5
    content-type: application/json
    x-ccf-tx-seqno: 23
    x-ccf-tx-view: 2

    true

The HTTP response some CCF commit information in the headers:

- ``"x-ccf-tx-seqno"`` is the unique version at which the request was executed
- ``"x-ccf-tx-view"`` indicates the consensus view at which the request was executed

The response body (the JSON value ``true``) indicates that the request was executed successfully. For many RPCs this will be a JSON object with more details about the execution result.

Signing
-------

In some situations CCF requires signed requests, for example for member votes.
The signing scheme is compatible with the `IETF HTTP Signatures draft RFC <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_.
We provide a wrapper script (``scurl.sh``) around ``curl`` to submit signed requests from the command line.

CCF identifies the signing identity for a request via the SHA-256 digest of its certificate, represented as a hex string.
That value must be set in the ``keyId`` field of the ``Authorization`` HTTP header for a signed request.

These commands can also be signed and transmitted by external libraries.
For example, the CCF test infrastructure uses `an auth plugin <https://pypi.org/project/requests-http-signature/>`_ for `Python Requests <https://requests.readthedocs.io/en/master/>`_.

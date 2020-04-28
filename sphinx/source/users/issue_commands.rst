Issuing Commands
================

Clients communicate with CCF using HTTP requests.

These requests can be sent by standard tools. CCF's test infrastructure uses `Python Requests <https://requests.readthedocs.io/en/master/>`_ by default, but can be switched to a ``curl``-based client (printing each command to stdout) by running with environment variable ``CURL_CLIENT`` set.

For example, to record a message at a specific id with the :ref:`developers/example:Example Application`, using curl:

.. code-block:: bash

    $ cat request.json
    {
      "id": 42,
      "msg": "Hello There"
    }

    $ curl https://<ccf-node-address>/users/LOG_record --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @request.json -H "content-type: application/json" -i
    HTTP/1.1 200 OK
    content-length: 5
    content-type: application/json
    x-ccf-commit: 23
    x-ccf-global-commit: 22
    x-ccf-term: 2

    true

The HTTP response some CCF commit information in the headers:

- ``"x-ccf-commit"`` is the unique version at which the request was executed
- ``"x-ccf-global-commit"`` is the latest version agreed on by the network and forever committed to the ledger, at the time the request was executed, as seen by the contacted node
- ``"x-ccf-term"`` indicates the consensus term at which the request was executed

The response body (the JSON value ``true``) indicates that the request was executed successfully. For many RPCs this will be a JSON object with more details about the execution result.

Signing
-------

In some situations CCF requires signed requests, for example for member votes. The signing scheme is compatible with the `IETF HTTP Signatures draft RFC <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_. We provide a wrapper script (``scurl.sh``) around curl to submit signed requests from the command line.

These commands can also be signed and transmitted by external libraries. For example, the CCF test infrastructure uses `an auth plugin <https://pypi.org/project/requests-http-signature/>`_ for `Python Requests <https://requests.readthedocs.io/en/master/>`_.

Python Client
-------------

Available as part of CCF Python infra: https://github.com/microsoft/CCF/blob/master/tests/infra/clients.py.

The ``Checker`` class in `ccf.py <https://github.com/microsoft/CCF/blob/master/tests/infra/ccf.py>`_ can be used as a wrapper to wait for requests to be committed.

Checking for Commit
-------------------

Because of the decentralised nature of CCF, a request is committed to the ledger only once a number of nodes have agreed on that request.

To guarantee that their request is successfully committed to the ledger, a user should issue a ``getTxStatus`` request, specifying the transaction version received in the response. The response may say the initial transaction is still pending global commit, has been globally committed, or has been lost due to a consensus leadership change (in which case the request should be resubmitted).

.. code-block:: bash

    $ curl -X GET "https://127.244.92.148:39297/users/getTxStatus?view=2&index=18" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem -i
    HTTP/1.1 200 OK
    content-length: 23
    content-type: application/json
    x-ccf-commit: 42
    x-ccf-global-commit: 40
    x-ccf-term: 5

    {"status":"COMMITTED"}

This example queries the status of the request versioned at index 18, in view 2 (written 2.18 for conciseness). The response indicates this was successfully committed. Note that once a request has been assigned a version number, this version number will never be associated with a different transaction. In normal operation, the next requests will be given versions 2.19, then 2.20, and so on, and after a short delay 2.18 will be globally committed. If the network is unable to reach consensus then it will trigger a leadership election. In this case the user's next request may be given a version 3.16, followed by 3.17, then 3.18. The index is reused, but in a different term; the service knows that 2.18 can never be assigned, so it has been lost.

Transaction receipts
--------------------

Once a transaction has been committed, it is possible to get a receipt for it. That receipt can later be checked against either a CCF service, or offline against the ledger, to prove that the transaction did happen at a particular commit.

To obtain a receipt, a user needs to issue a ``getReceipt`` RPC for a particular commit:

.. code-block:: bash

    $ cat get_receipt.json
    {
      "commit": 23
    }

    $ curl https://<ccf-node-address>/users/getReceipt --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @get_receipt.json -H "content-type: application/json"
    {
      "receipt": [ ... ],
    }

Receipts can be verified with the ``verifyReceipt`` RPC:

.. code-block:: bash

    $ cat verify_receipt.json
    {
      "receipt": [ ... ]
    }

    $ curl https://<ccf-node-address>/users/verifyReceipt --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @verify_receipt.json
    {
      "valid": true,
    }

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

To guarantee that their request is successfully committed to the ledger, a user needs to issue a ``getCommit`` request, specifying the ``commit`` version received in the response. If CCF returns a ``global-commit`` greater than the ``commit`` version at which the ``LOG_record`` request was issued `and` that result ``commit`` is in the same ``term``, then the request was committed to the ledger.

.. code-block:: bash

    $ cat get_commit.json
    {
      "commit": 23
    }

    $ curl https://<ccf-node-address>/users/getCommit --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @get_commit.json -H "content-type: application/json" -i
    HTTP/1.1 200 OK
    content-length: 32
    content-type: application/json
    x-ccf-commit: 33
    x-ccf-global-commit: 33
    x-ccf-term: 2

    {
      "commit": 23,
      "term": 2
    }

In this example, the ``result`` field indicates that the request was executed at ``23`` (``commit``), and in term ``2``, the same term that the ``LOG_record`` executed in. Moreover, the ``global_commit`` (``33``) is now greater than the ``commit`` version. The ``LOG_record`` request issued earlier was successfully committed to the ledger.

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

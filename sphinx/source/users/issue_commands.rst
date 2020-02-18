Issuing Commands
================

Clients communicate with CCF using HTTP requests. Currently all requests must use the HTTP method ``POST``, and the body of each request is expected to be a valid JSON-RPC object. Arbitrary payload and return types will be supported in future. The ``method`` must be prefixed with the name of the target frontend (``"users"`` or ``"members"``), separated from the intended ``method`` with a single ``/``, and this ``method`` must also match the resource path in the URL.

These requests can be sent by standard tools. CCF's test infrastructure uses `Python Requests <https://requests.readthedocs.io/en/master/>`_ by default, but can be switched to a ``curl``-based client (printing each command to stdout) by running with environment variable ``CURL_CLIENT`` set.

For example, to record a message at a specific id with the :ref:`developers/example:Example Application`, using curl:

.. code-block:: bash

    $ cat request.json
    {
      "id": 0,
      "method": "users/LOG_record",
      "jsonrpc": "2.0",
      "params":
      {
        "id": 42,
        "msg": "Hello There"
      }
    }

    $ curl https://<ccf-node-address>/users/LOG_record --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @request.json
    {
      "commit": 23,
      "global_commit": 22,
      "id": 0,
      "jsonrpc": "2.0",
      "result": true,
      "term": 2
    }

The HTTP response contains a JSON-RPC response object, extended with some CCF commit information:

- ``"id"`` indicates that the response matches the request sent with id ``0``
- ``"result": true`` indicates that the request was executed successfully, for other RPCs this may be an arbitrary JSON object
- ``"commit"`` is the unique version at which the request was executed
- ``"global_commit"`` is the latest version agreed on by the network and forever committed to the ledger, at the time the request was executed, as seen by the contacted node
- ``"term"`` indicates the consensus term at which the request was executed

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

To guarantee that their request is successfully committed to the ledger, a user needs to issue a ``getCommit`` request, specifying the ``commit`` version received in the JSON-RPC response. If CCF returns a ``global_commit`` greater than the ``commit`` version at which the ``LOG_record`` request was issued `and` that the result ``commit`` is in the same ``term``, then the request was committed to the ledger.

.. code-block:: bash

    $ cat get_commit.json
    {
      "id": 0,
      "method": "users/getCommit",
      "jsonrpc": "2.0",
      "params":
      {
        "commit": 30
      }
   }

    $ curl https://<ccf-node-address>/users/getCommit --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @get_commit.json
    {
      "commit": 31,
      "global_commit": 31,
      "id": 0,
      "jsonrpc": "2.0",
      "result": {
        "commit": 30,
        "term": 2
      },
      "term": 2
    }

In this example, the ``result`` field indicates that the request was executed at ``30`` (``commit``) was in term ``2``, the same term that the ``LOG_record``. Moreover, the ``global_commit`` (``31``) is now greater than the ``commit`` version. The ``LOG_record`` request issued earlier was successfully committed to the ledger.

Transaction receipts
--------------------

Once a transaction has been committed, it is possible to get a receipt for it. That receipt can later be checked against either a CCF service, or offline against the ledger, to prove that the transaction did happen at a particular commit.

To obtain a receipt, a user needs to issue a ``getReceipt`` RPC for a particular commit:

.. code-block:: bash

    $ cat get_receipt.json
    {
      "id": 0,
      "method": "users/getReceipt",
      "jsonrpc": "2.0",
      "params":
      {
        "commit": 30
      }
   }

    $ curl https://<ccf-node-address>/users/getReceipt --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @get_receipt.json
    {
      "commit": 31,
      "global_commit": 31,
      "id": 0,
      "jsonrpc": "2.0",
      "result": {
        "receipt": [ ... ],
      },
      "term": 2
    }

Receipts can be verified with the ``verifyReceipt`` RPC:

.. code-block:: bash

    $ cat verify_receipt.json
    {
      "id": 0,
      "method": "users/verifyReceipt",
      "jsonrpc": "2.0",
      "params":
      {
        "receipt": [ ... ]
      }
   }

    $ curl https://<ccf-node-address>/users/verifyReceipt --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @verify_receipt.json
    {
      "commit": 31,
      "global_commit": 31,
      "id": 0,
      "jsonrpc": "2.0",
      "result": {
        "valid": true,
      },
      "term": 2
    }

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

    $ curl https://<ccf-node-address>/users/log/private --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @request.json -H "content-type: application/json" -i
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

In some situations CCF requires signed requests, for example for member votes. The signing scheme is compatible with the `IETF HTTP Signatures draft RFC <https://tools.ietf.org/html/draft-cavage-http-signatures-12>`_. We provide a wrapper script (``scurl.sh``) around curl to submit signed requests from the command line.

These commands can also be signed and transmitted by external libraries. For example, the CCF test infrastructure uses `an auth plugin <https://pypi.org/project/requests-http-signature/>`_ for `Python Requests <https://requests.readthedocs.io/en/master/>`_.

Python Client
-------------

Available as part of CCF Python infra: https://github.com/microsoft/CCF/blob/master/tests/infra/clients.py.

The ``Checker`` class in `ccf.py <https://github.com/microsoft/CCF/blob/master/tests/infra/ccf.py>`_ can be used as a wrapper to wait for requests to be committed.

Checking for Commit
-------------------

Because of the decentralised nature of CCF, a request is committed to the ledger only once a number of nodes have agreed on that request.

To guarantee that their request is successfully committed to the ledger, a user should issue a ``GET /tx`` request, specifying the version received in the response. This version is constructed from a view and a sequence number.

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/tx?view=2&seqno=18" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem -i
    HTTP/1.1 200 OK
    content-length: 23
    content-type: application/json
    x-ccf-tx-seqno: 42
    x-ccf-tx-view: 5

    {"status":"COMMITTED"}

This example queries the status of transaction ID 2.18 (constructed from view 2 and sequence number 18). The response indicates this was successfully committed. The headers also show that the service has since made progress with other requests, and global commit index has continued to increase.

The possible statuses are:

- ``UNKNOWN`` - this node has not received a transaction with the given ID
- ``PENDING`` - this node has received a transaction with the given ID, but does not yet know if the transaction has been committed
- ``COMMITTED`` - this node knows that this transaction is committed, it is an irrevocable and durable part of the service's transaction history
- ``INVALID`` - this node knows that the given transaction cannot be committed. This occurs when the view changes, and some pending transactions may be lost and must be resubmitted, but also applies to IDs which are known to be impossible given the current globally committed IDs

On a given node, the possible transitions between states are described in the following diagram:

.. mermaid::

    stateDiagram
        Unknown --> Pending
        Pending --> Committed
        Pending --> Invalid

It is possible that intermediate states are not visible (eg - a transition from Unknown to Committed may never publically show a Pending result). Nodes may disagree on the current state due to communication delays, but will never disagree on transitions (in other words, they may believe a Committed transaction is still Unknown or Pending, but will never report it as Invalid).

Note that transaction IDs are uniquely assigned by the service - once a request has been assigned an ID, this ID will never be associated with a different write transaction. In normal operation, the next requests will be given versions 2.19, then 2.20, and so on, and after a short delay 2.18 will be committed. If requests are submitted in parallel, they will be applied in a consistent order indicated by their assigned versions. If the network is unable to reach consensus, it will trigger a leadership election which increments the view. In this case the user's next request may be given a version 3.16, followed by 3.17, then 3.18. The sequence number is reused, but in a different view; the service knows that 2.18 can never be assigned, so it can report this as an invalid ID. Read-only transactions are an exception - they do not get a unique transaction ID but instead return the ID of the last write transaction whose state they may have read.

Transaction receipts
--------------------

Once a transaction has been committed, it is possible to get a receipt for it. That receipt can later be checked against either a CCF service, or offline against the ledger, to prove that the transaction did happen at a particular commit.

To obtain a receipt, a user needs to issue a ``getReceipt`` RPC for a particular commit:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/getReceipt?commit=23" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem
    {
      "receipt": [ ... ],
    }

Receipts can be verified with the ``verifyReceipt`` RPC:

.. code-block:: bash

    $ cat verify_receipt.json
    {
      "receipt": [ ... ]
    }

    $ curl https://<ccf-node-address>/app/verifyReceipt --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @verify_receipt.json
    {
      "valid": true,
    }

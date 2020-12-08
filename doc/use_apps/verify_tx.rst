Verifying Transaction
=====================

Checking for Commit
-------------------

.. note:: As part of the :doc:`CCF Python package <python_tutorial>`, the ``wait_for_commit()`` method can be used to verify that a transaction has successfully been committed.

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

This example queries the status of transaction ID ``2.18`` (constructed from view ``2`` and sequence number ``18``). The response indicates this was successfully committed. The headers also show that the service has since made progress with other requests (``x-ccf-tx-seqno: 42``) and changed view (``x-ccf-tx-view: 5``).

The possible statuses returned by ``GET /tx`` are:

- ``UNKNOWN`` - this node has not received a transaction with the given ID
- ``PENDING`` - this node has received a transaction with the given ID, but does not yet know if the transaction has been committed
- ``COMMITTED`` - this node knows that this transaction is committed, it is an irrevocable and durable part of the service's transaction history
- ``INVALID`` - this node knows that the given transaction cannot be committed. This occurs when the view changes, and some pending transactions may be lost and must be resubmitted, but also applies to IDs which are known to be impossible given the current committed IDs

On a given node, the possible transitions between states are described in the following diagram:

.. mermaid::

    stateDiagram
        UNKNOWN --> PENDING
        PENDING --> COMMITTED
        PENDING --> INVALID

It is possible that intermediate states are not visible (e.g. a transition from ``UNKNOWN`` to ``COMMITTED`` may never publically show a ``PENDING`` result). Nodes may disagree on the current state due to communication delays, but will never disagree on transitions (in other words, they may believe a ``COMMITTED`` transaction is still ``UNKNOWN`` or ``PENDING``, but will never report it as ``INVALID``).

Note that transaction IDs are uniquely assigned by the service - once a request has been assigned an ID, this ID will never be associated with a different write transaction. In normal operation, the next requests will be given versions 2.19, then 2.20, and so on, and after a short delay ``2.18`` will be committed. If requests are submitted in parallel, they will be applied in a consistent order indicated by their assigned versions.

If the network is unable to reach consensus, it will trigger a leadership election which increments the view. In this case the user's next request may be given a version ``3.16``, followed by ``3.17``, then ``3.18``. The sequence number is reused, but in a different view; the service knows that ``2.18`` can never be assigned, so it can report this as an invalid ID. Read-only transactions are an exception - they do not get a unique transaction ID but instead return the ID of the last write transaction whose state they may have read.

Transaction Receipts
--------------------

Once a transaction has been committed, it is possible to get a receipt for it. That receipt can later be checked against either a CCF service, or offline against the ledger, to prove that the transaction did happen at a particular commit.

To obtain a receipt, a user needs to issue a ``GET /receipt`` RPC for a particular commit:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?commit=23" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem
    {
      "receipt": [ ... ],
    }

Receipts can be verified with the ``POST /receipt/verify`` RPC:

.. code-block:: bash

    $ cat verify_receipt.json
    {
      "receipt": [ ... ]
    }

    $ curl https://<ccf-node-address>/app/receipt/verify --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem --data-binary @verify_receipt.json
    {
      "valid": true,
    }

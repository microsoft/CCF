Verifying Transactions
======================

Checking for Commit
-------------------

.. note:: As part of the :doc:`CCF Python package <python_tutorial>`, the ``wait_for_commit()`` method can be used to verify that a transaction has successfully been committed.

Because of the decentralised nature of CCF, a request is committed to the ledger only once a number of nodes have agreed on that request.

To guarantee that their request is successfully committed to the ledger, a user should issue a :http:GET:`/app/tx` request, specifying the version received in the response. This version is constructed from a view and a sequence number.

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/tx?transaction_id=2.18" --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem -i
    HTTP/1.1 200 OK
    content-length: 23
    content-type: application/json
    x-ms-ccf-transaction-id: 5.42

    {"status":"COMMITTED"}

This example queries the status of transaction ID ``2.18`` (constructed from view ``2`` and sequence number ``18``). The response indicates this was successfully committed. The headers also show that the service has since made progress with other requests and changed view (``x-ms-ccf-transaction-id: 5.42``).

The possible statuses returned by :http:GET:`/app/tx` are:

- ``UNKNOWN`` - this node has not received a transaction with the given ID
- ``PENDING`` - this node has received a transaction with the given ID, but does not yet know if the transaction has been committed
- ``COMMITTED`` - this node knows that this transaction is committed, it is an irrevocable and durable part of the service's transaction history
- ``INVALID`` - this node knows that the given transaction cannot be committed. This occurs when the view changes, and some pending transactions may be lost and must be resubmitted, but also applies to IDs which are known to be impossible given the current committed IDs

On a given node, the possible transitions between states are described in the following diagram:

.. mermaid::

    stateDiagram
        UNKNOWN --> PENDING
        PENDING --> UNKNOWN
        PENDING --> COMMITTED
        PENDING --> INVALID

It is possible that intermediate states are not visible (e.g. a transition from ``UNKNOWN`` to ``COMMITTED`` may never publically show a ``PENDING`` result). Nodes may disagree on the current state due to communication delays, but will never disagree on transitions (in other words, they may believe a ``COMMITTED`` transaction is still ``UNKNOWN`` or ``PENDING``, but will never report it as ``INVALID``). A transition from ``PENDING`` to ``UNKNOWN`` can only occur immediately after an election, while the node is confirming where the new view starts, and will usually resolve to ``COMMITTED`` or ``PENDING`` quickly afterwards.

Note that transaction IDs are uniquely assigned by the service - once a request has been assigned an ID, this ID will never be associated with a different write transaction. In normal operation, the next requests will be given versions 2.19, then 2.20, and so on, and after a short delay ``2.18`` will be committed. If requests are submitted in parallel, they will be applied in a consistent order indicated by their assigned versions.

If the network is unable to reach consensus, it will trigger a leadership election which increments the view. In this case the user's next request may be given a version ``3.16``, followed by ``3.17``, then ``3.18``. The sequence number is reused, but in a different view; the service knows that ``2.18`` can never be assigned, so it can report this as an invalid ID. Read-only transactions are an exception - they do not get a unique transaction ID but instead return the ID of the last write transaction whose state they may have read.

.. note:: To verify a transaction offline, see :ref:`receipts <audit/receipts:Receipts>`.

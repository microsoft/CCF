Verifying Transaction
=====================

Checking for Commit
-------------------

.. note:: As part of the :doc:`CCF Python package <python_tutorial>`, the ``wait_for_commit()`` method can be used to verify that a transaction has successfully been committed.

Because of the decentralised nature of CCF, a request is committed to the ledger only once a number of nodes have agreed on that request.

To guarantee that their request is successfully committed to the ledger, a user should issue a ``GET /tx`` request, specifying the version received in the response. This version is constructed from a view and a sequence number.

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/tx?transaction_id=2.18" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem -i
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
        PENDING --> UNKNOWN
        PENDING --> COMMITTED
        PENDING --> INVALID

It is possible that intermediate states are not visible (e.g. a transition from ``UNKNOWN`` to ``COMMITTED`` may never publically show a ``PENDING`` result). Nodes may disagree on the current state due to communication delays, but will never disagree on transitions (in other words, they may believe a ``COMMITTED`` transaction is still ``UNKNOWN`` or ``PENDING``, but will never report it as ``INVALID``). A transition from ``PENDING`` to ``UNKNOWN`` can only occur immediately after an election, while the node is confirming where the new view starts, and will usually resolve to ``COMMITTED`` or ``PENDING`` quickly afterwards.

Note that transaction IDs are uniquely assigned by the service - once a request has been assigned an ID, this ID will never be associated with a different write transaction. In normal operation, the next requests will be given versions 2.19, then 2.20, and so on, and after a short delay ``2.18`` will be committed. If requests are submitted in parallel, they will be applied in a consistent order indicated by their assigned versions.

If the network is unable to reach consensus, it will trigger a leadership election which increments the view. In this case the user's next request may be given a version ``3.16``, followed by ``3.17``, then ``3.18``. The sequence number is reused, but in a different view; the service knows that ``2.18`` can never be assigned, so it can report this as an invalid ID. Read-only transactions are an exception - they do not get a unique transaction ID but instead return the ID of the last write transaction whose state they may have read.

Transaction Receipts
--------------------

Once a transaction has been committed, it is possible to get a cryptographic receipt over the entry produced in the ledger. That receipt can be verified offline.

To obtain a receipt, a user needs to call a :http:get:`/receipt` for a particular transaction ID. Because fetching the information necessary to produce a receipt likely involves a round trip to the ledger, the endpoint is implemented as a historical query.
This means that the request may return ``202 Accepted`` at first, with a suggested ``Retry-After`` header. A subsequent call will return the actual receipt, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.23" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem
    
    {'leaf': 'fdc977c49d3a8bdf986176984e9432a09b5f6fe0c04e0b1c2dd177c03fdca9ec',
     'node_id': '682c161e1bc0aec694cac58a6ea456e1caa6c9c56d8dd873da9455c341947065',
     'proof': [{'left': 'f847e5efe3965b0dacb5c15c666602807a11fdecd465d0976779eed27121ffa3'},
               {'left': 'a56ce9efb73957f561f12d60513281fd2aaf16440234e2fd56e7d3d2ff4be8b0'},
               {'left': 'd91c982f525302244b13b6add92cd0925e1e0fb621ff2a7bb408ecc51be8528e'},
               {'left': '6d87faceda763ce65914f95dfcc04b37ea3f26bc552764752a0f2720039f76be'},
               {'left': 'e0cc83ea2fae6c535fc44605fb25ba9fdfb319e0e577b3541760f9a3565c549b'},
               {'left': 'f0e95ed85f5f6c0197aed4f6685b93dc56edd823a2532bd717558a5ab77267cb'}],
     'root': '06fef62c80b6471c7005c1b114166fd1b0e077845f5ad544ad4eea4fb1d31f78',
     'signature': 'MGQCMACklXqd0ge+gBS8WzewrwtwzRzSKy+bfrLZVx0YHmQvtsqs7dExYESsqrUrB8ZcKwIwS3NPKaGq0w2QlPlCqUC3vQoQvhcZgPHPu2GkFYa7JEOdSKLknNPHaCRv80zx2RGF'}

Note that receipts over signature transactions are a special case, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.35" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem
    
    {'leaf': 'fdc977c49d3a8bdf986176984e9432a09b5f6fe0c04e0b1c2dd177c03fdca9ec',
     'node_id': '06fef62c80b6471c7005c1b114166fd1b0e077845f5ad544ad4eea4fb1d31f78',
     'proof': [],
     'root': '06fef62c80b6471c7005c1b114166fd1b0e077845f5ad544ad4eea4fb1d31f78',
     'signature': 'MGQCMACklXqd0ge+gBS8WzewrwtwzRzSKy+bfrLZVx0YHmQvtsqs7dExYESsqrUrB8ZcKwIwS3NPKaGq0w2QlPlCqUC3vQoQvhcZgPHPu2GkFYa7JEOdSKLknNPHaCRv80zx2RGF'}

The proof is empty, and the 'leaf' and 'root' fields are both set to the value being signed, which is the root of the Merkle Tree covering all transactions until the signature.
This allows writing verification code that handles both regular and signature receipts without special casing, but it is worth noting that the 'leaf' value for signatures is not
the digest of the signature transaction itself.

Verifying a receipt is a two-phase process:

  - Combine ``leaf`` with the successive elements in ``proof`` to reproduce the value of ``root``. See :py:func:`ccf.receipt.root` for a reference implementation.
  - Verify ``signature`` over the ``root`` using the certificate of the node identified by ``node_id``. See :py:func:`ccf.receipt.verify` for a reference implementation.

When a node certificate is first obtained, it is necessary to check it has been endorsed by the network identity.
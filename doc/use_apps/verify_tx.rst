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

Write Receipts
--------------

Once a transaction has been committed, it is possible to get a cryptographic receipt over the entry produced in the ledger. That receipt can be verified offline.

To obtain a receipt, a user needs to call a :http:GET:`/node/receipt` for a particular transaction ID. Because fetching the information necessary to produce a receipt likely involves a round trip to the ledger, the endpoint is implemented as a historical query.
This means that the request may return ``202 Accepted`` at first, with a suggested ``Retry-After`` header. A subsequent call will return the actual receipt, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.643" --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem

    {'cert': '-----BEGIN CERTIFICATE-----\n'
            'MIIBzjCCAVSgAwIBAgIQGR/ue9CFspRa/g6jSMHFYjAKBggqhkjOPQQDAzAWMRQw\n'
            'EgYDVQQDDAtDQ0YgTmV0d29yazAeFw0yMjAxMjgxNjAzNDZaFw0yMjAxMjkxNjAz\n'
            'NDVaMBMxETAPBgNVBAMMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\n'
            'wsdpHLNw7xso/g71XzlQjoITiTBOef8gCayOiPJh/W2YfzreOawzD6gVQPSI+iPg\n'
            'ZPc6smFhtV5bP/WZ2KW0K9Pn+OIjm/jMU5+s3rSgts50cRjlA/k81bUI88dzQzx9\n'
            'o2owaDAJBgNVHRMEAjAAMB0GA1UdDgQWBBQgtPwYar54AQ4UL0RImVsm6wQQpzAf\n'
            'BgNVHSMEGDAWgBS2ngksRlVPvwDcLhN57VV+j2WyBTAbBgNVHREEFDAShwR/AAAB\n'
            'hwR/ZEUlhwR/AAACMAoGCCqGSM49BAMDA2gAMGUCMQDq54yS4Bmfwfcikpy2yL2+\n'
            'GFemyqNKXheFExRVt2edxVgId+uvIBGjrJEqf6zS/dsCMHVnBCLYRgxpamFkX1BF\n'
            'BDkVitfTOdYfUDWGV3MIMNdbam9BDNxG4q6XtQr4eb3jqg==\n'
            '-----END CERTIFICATE-----\n',
    'leaf_components': {'commit_evidence': 'ce:2.643:55dbbbf04b71c6dcc01dd9d1c0012a6a959aef907398f7e183cc8913c82468d8',
                        'write_set_digest': 'd0c521504ce2be6b4c22db8e99b14fc475b51bc91224181c75c64aa2cef72b83'},
    'node_id': '7dfbb9a56ebe8b43c833b34cb227153ef61e4890187fe6164022255dec8f9646',
    'proof': [{'left': '00a771baf15468ed05d6ef8614b3669fcde6809314650061d64281b5d4faf9ec'},
              {'left': 'a9c8a36d01aa9dfbfb74c6f6a2cef2efcbd92bd6dfd1f7440302ad5ac7be1577'},
              {'right': '8e238d95767e6ffe4b20e1a5e93dd7b926cbd86caa83698584a16ad2dd7d60b8'},
              {'left': 'd4717996ae906cdce0ac47257a4a9445c58474c2f40811e575f804506e5fee9f'},
              {'left': 'c1c206c4670bd2adee821013695d593f5983ca0994ae74630528da5fb6642205'}],
    'signature': 'MGQCMHrnwS123oHqUKuQRPsQ+gk6WVutixeOvxcXX79InBgPOxJCoScCOlBnK4UYyLzangIwW9k7IZkMgG076qVv5zcx7OuKb7bKyii1yP1rcakeGVvVMwISeE+Fr3BnFfPD66Df'}

Note that receipts over signature transactions are a special case, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.35" --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem

    {'leaf': 'fdc977c49d3a8bdf986176984e9432a09b5f6fe0c04e0b1c2dd177c03fdca9ec',
     'node_id': '06fef62c80b6471c7005c1b114166fd1b0e077845f5ad544ad4eea4fb1d31f78',
     'proof': [],
     'signature': 'MGQCMACklXqd0ge+gBS8WzewrwtwzRzSKy+bfrLZVx0YHmQvtsqs7dExYESsqrUrB8ZcKwIwS3NPKaGq0w2QlPlCqUC3vQoQvhcZgPHPu2GkFYa7JEOdSKLknNPHaCRv80zx2RGF',
     'cert': '<PEM string>'}

The proof is empty, and the 'leaf' field is set to the value being signed, which is the root of the Merkle Tree covering all transactions until the signature.
This allows writing verification code that handles both regular and signature receipts similarly, but it is worth noting that the 'leaf' value for signatures is not
the digest of the signature transaction itself.

Verifying a receipt involves the following steps:

  - Digest ``commit_evidence`` to produce ``commit_evidence_digest`` and ``claims`` to produce ``claims_digest`` when applicable.
  - If the receipt contains ``leaf_components``, digest the concatenation ``write_set_digest + commit_evidence_digest + claims_digest`` to produce ``leaf``.
  - Combine ``leaf`` with the successive elements in ``proof`` to calculate the value of ``root``. See :py:func:`ccf.receipt.root` for a reference implementation.
  - Verify ``signature`` over the ``root`` using the certificate of the node identified by ``node_id`` and ``cert``. See :py:func:`ccf.receipt.verify` for a reference implementation.
  - Check that the certificate ``cert`` of ``node_id`` used to sign the receipt is endorsed by the CCF network. See :py:func:`ccf.receipt.check_endorsement` for a reference implementation.

Application Claims
------------------

TBD
Verifying Transactions
======================

Checking for Commit
-------------------

Because of the decentralised nature of CCF, a request is committed to the ledger only once a number of nodes have agreed on that request.

To guarantee that their request is successfully committed to the ledger, a user should issue a :http:GET:`/app/tx` request, specifying the version received in the response. This version is constructed from a view and a sequence number.

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/tx?transaction_id=2.18" --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem -i
    HTTP/1.1 200 OK
    content-length: 23
    content-type: application/json
    x-ms-ccf-transaction-id: 5.42

    {"status":"COMMITTED"}

This example queries the status of :term:`Transaction ID` ``2.18`` (constructed from view ``2`` and sequence number ``18``). The response indicates this was successfully committed. The headers also show that the service has since made progress with other requests and changed view (``x-ms-ccf-transaction-id: 5.42``).

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

If the network is unable to reach consensus, it will trigger a leadership election which increments the view. In this case the user's next request may be given a version ``3.16``, followed by ``3.17``, then ``3.18``. The sequence number is reused, but in a different view; the service knows that ``2.18`` can never be assigned, so it can report this as an invalid ID. Read-only transactions are an exception - they do not get a unique :term:`Transaction ID` but instead return the ID of the last write transaction whose state they may have read.

Write Receipts
--------------

Once a transaction has been committed, it is possible to get a cryptographic receipt over the entry produced in the ledger. That receipt can be verified offline.

To obtain a receipt, a user needs to call a :http:GET:`/app/receipt` for a particular :term:`Transaction ID`. Because fetching the information necessary to produce a receipt likely involves a round trip to the ledger, the endpoint is implemented as a historical query.
This means that the request may return ``202 Accepted`` at first, with a suggested ``Retry-After`` header. A subsequent call will return the actual receipt, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.643" --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem

    {'cert': '-----BEGIN CERTIFICATE-----\n'
            'MIIBzzCCAVWgAwIBAgIRANoNTgf6hwugwIZgb/vrSXcwCgYIKoZIzj0EAwMwFjEU\n'
            'MBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwNDI1MTUwMTMzWhcNMjIwNDI2MTUw\n'
            'MTMyWjATMREwDwYDVQQDDAhDQ0YgTm9kZTB2MBAGByqGSM49AgEGBSuBBAAiA2IA\n'
            'BCbH0j1tcyHeyBVxThuzwyk6IesLFe6CXBqOYBbEvrLCrdR+wj400UR0xWBcVroY\n'
            '8GqF+tLS8YQPt+kepG82lZuRjAbaBn2BL8g6cdKGOew5fo9LCL9+NlH+W6bz83E/\n'
            'Z6NqMGgwCQYDVR0TBAIwADAdBgNVHQ4EFgQUlMCr5/1LIzGegZPJfHwzFl5GCwUw\n'
            'HwYDVR0jBBgwFoAUuzKYZ+UZum8NaytcWRfirw8TA+MwGwYDVR0RBBQwEocEfwAA\n'
            'AYcEf7i1MYcEfwAAAjAKBggqhkjOPQQDAwNoADBlAjEAyLPRWCR4Nn0Z3q/1rKCc\n'
            'ppiSwPrMQ/asHoUAUgmnAGkxgJ6A8iGJXa/WFal/PDtdAjBfp+AIkuVcBjmWfLxF\n'
            'MKN7njz6Q9m10APn+KigsvS4aIRbHZHbYTkAOyFEdipm5gA=\n'
            '-----END CERTIFICATE-----\n',
    'leaf_components': {'claims_digest': '0000000000000000000000000000000000000000000000000000000000000000',
                        'commit_evidence': 'ce:2.500:a4e526cef8d1155e8a8c5f4c0dd8d1220c924cea620e1cc737c4039c8abc8d6b',
                        'write_set_digest': '56f1f53e61a80606fec984cbfadaf833b3bb2e68f464f3b7c641e163fcb1f647'},
    'node_id': 'c0718b67b986748d074a293201fa2f9bc3a29e07d204ccc24167afdc59bdf0c3',
    'proof': [{'left': '26e7edf1065e23a387b8d6fd3743b4885aae1919c4c347d73b792e3e77b57695'},
            {'left': '76c79df9146479c0aebdd51f228e1d304d60f382f61571a729f2fba7d93ce2a7'},
            {'left': '6b54d109e3f474f9f546d5d462de40440ca335b133d3899c228532fcc535e732'},
            {'left': 'bf3e529174209df204342224fc39ffee68189c30db03e53ba1d4baa053e02471'},
            {'left': '740dcdb82afe5f2b311056c96bd6afcc1b571e1cdb8e918bfe24eda48213eb1a'},
            {'left': '05efd90dfd3bf86a3efa185c6a869342cb0d9af4dd92256d37dc826b86e99684'}],
    'signature': 'MGYCMQCI1yY5xhGNFXyKjO6mFhxZCjAsuTsquO1agIzKkxh/Uf9Em+P7AwnxuQ2uC7WU++QCMQCSzpE9k8xkSku5BlkUelDPBHxLuokLIpKAyn73HXtXiz+zXOVWIZkYftUEoQ31pG0='}

`cert` contains the certificate of the signing node, endorsed by the service identity. `node_id` is the node's ID inside CCF, a digest of its public key.

Note that receipts over signature transactions are a special case, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.35" --cacert service_cert.pem --key user0_privk.pem --cert user0_cert.pem

    {'leaf': 'fdc977c49d3a8bdf986176984e9432a09b5f6fe0c04e0b1c2dd177c03fdca9ec',
     'node_id': '06fef62c80b6471c7005c1b114166fd1b0e077845f5ad544ad4eea4fb1d31f78',
     'proof': [],
     'signature': 'MGQCMACklXqd0ge+gBS8WzewrwtwzRzSKy+bfrLZVx0YHmQvtsqs7dExYESsqrUrB8ZcKwIwS3NPKaGq0w2QlPlCqUC3vQoQvhcZgPHPu2GkFYa7JEOdSKLknNPHaCRv80zx2RGF',
     'cert': '<PEM string>'}

The proof is empty, and the ``leaf`` field is set to the value being signed, which is the root of the Merkle Tree covering all transactions until the signature.
This allows writing verification code that handles both regular and signature receipts similarly, but it is worth noting that the 'leaf' value for signatures is `not`
the digest of the signature transaction itself.

From version 2.0, CCF also includes endorsement certificates for previous service identities, by the current service identity, in `service_endorsements`. Thus, after at least one recovery, the endorsement check now takes the form of a certificate chain verification instead of a single endorsement check.

Receipt Verification
--------------------

Verifying a receipt consists of the following steps:

  1. Digest ``commit_evidence`` to produce ``commit_evidence_digest`` and ``claims`` to produce ``claims_digest`` when applicable.
  2. If the receipt contains ``leaf_components``, digest the concatenation ``write_set_digest + commit_evidence_digest + claims_digest`` to produce ``leaf``.
  3. Combine ``leaf`` with the successive elements in ``proof`` to calculate the value of ``root``. See :py:func:`ccf.receipt.root` for a reference implementation.
  4. Verify ``signature`` over the ``root`` using the certificate of the node identified by ``node_id`` and ``cert``. See :py:func:`ccf.receipt.verify` for a reference implementation.
  5. Check that the certificate ``cert`` of ``node_id`` used to sign the receipt is endorsed by the CCF network. See :py:func:`ccf.receipt.check_endorsements` for a reference implementation.

Note that since a receipt is a committment by a service to a transaction, a verifier must know the service identity, and provide it as an input to step 5.

Application Claims
------------------

CCF allows application code to attach arbitrary claims to a transaction, via the :cpp:func:`enclave::RpcContext::set_claims_digest` API, as illustrated in :ref:`build_apps/example_cpp:User-Defined Claims in Receipts`.

This is useful to allow the reveal and verification of application-related claims offline, ie. without access to the CCF network.
For example, a logging application may choose to set the digest of the payload being logged as ``claims_digest``.
A user who logs a payload can then present the receipt and the payload to a third party, who can confirm that they match, having verified the receipt. They can perform this verification without access to the service.

Multiple claims can be registered by storing them in a collection or object whose digest is set as ``claims_digest``. It is possible to reveal them selectively, by capturing their digest in turn, rather than their raw value directly, eg:

``claims_digest = hash( hash(claim_a) + hash(claim_b) )``

Revealing ``hash(claim_a)`` and ``claim_b`` allows verification without revealing ``claim_a`` in this case.

Although CCF takes the approach of concatenating leaf components to keep its implementation simple and format-agnostic, an application may choose to encode its claims in a structured way for convenience, for example as JSON, CBOR etc.

Applications may wish to expose dedicated endpoints, besides CCF's built-in :http:GET:`/node/receipt`, in which they can selectively expand claims, as illustrated in :ref:`build_apps/example_cpp:User-Defined Claims in Receipts`.
If some claims must stay confidential, applications should encrypt them rather than merely digest them. They key can be kept in a private table for example, which like the claim will be available through the historical query API. The application logic can then decide whether to decrypt the claim for the caller depending on its authorisation policy.

Commit Evidence
---------------

The ``commit_evidence`` field in receipts fulfills two purposes:

1. It exposes the full :term:`Transaction ID` in a format that is easy for a user to extract, and does not require parsing the ledger entry.
2. Because it cannot be extracted from the ledger without access to the ledger secrets, it guarantees the transaction is committed.

Entries are written out to the ledger as early as possible, to relieve memory pressure inside the enclave. If receipts could be produced from these entries regardless of their replication status, a malicious actor could emit them for transactions that have been tentatively run by a primary, appended to its local ledger, but since rolled back.
By including a committment to the digest of ``commit_evidence`` as a leaf component in the Merkle Tree, which is effectively a nonce derived from ledger secrets and TxID, we ensure that only receipts produced by nodes that can reveal this nonce are verifiable.
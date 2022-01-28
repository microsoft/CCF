Receipts
========

Write Receipts
--------------

Once a transaction has been committed, it is possible to get a cryptographic receipt over the entry produced in the ledger. That receipt can be verified offline.

To obtain a receipt, a user needs to call a :http:GET:`/node/receipt` for a particular transaction ID. Because fetching the information necessary to produce a receipt likely involves a round trip to the ledger, the endpoint is implemented as a historical query.
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
     'signature': 'MGQCMACklXqd0ge+gBS8WzewrwtwzRzSKy+bfrLZVx0YHmQvtsqs7dExYESsqrUrB8ZcKwIwS3NPKaGq0w2QlPlCqUC3vQoQvhcZgPHPu2GkFYa7JEOdSKLknNPHaCRv80zx2RGF',
     'cert': '<PEM string>'}

Note that receipts over signature transactions are a special case, for example:

.. code-block:: bash

    $ curl -X GET "https://<ccf-node-address>/app/receipt?transaction_id=2.35" --cacert networkcert.pem --key user0_privk.pem --cert user0_cert.pem

    {'leaf': 'fdc977c49d3a8bdf986176984e9432a09b5f6fe0c04e0b1c2dd177c03fdca9ec',
     'node_id': '06fef62c80b6471c7005c1b114166fd1b0e077845f5ad544ad4eea4fb1d31f78',
     'proof': [],
     'signature': 'MGQCMACklXqd0ge+gBS8WzewrwtwzRzSKy+bfrLZVx0YHmQvtsqs7dExYESsqrUrB8ZcKwIwS3NPKaGq0w2QlPlCqUC3vQoQvhcZgPHPu2GkFYa7JEOdSKLknNPHaCRv80zx2RGF',
     'cert': '<PEM string>'}

The proof is empty, and the 'leaf' field is set to the value being signed, which is the root of the Merkle Tree covering all transactions until the signature.
This allows writing verification code that handles both regular and signature receipts without special casing, but it is worth noting that the 'leaf' value for signatures is not
the digest of the signature transaction itself.

Verifying a receipt is a three-phase process:

  - Combine ``leaf`` with the successive elements in ``proof`` to calculate the value of ``root``. See :py:func:`ccf.receipt.root` for a reference implementation.
  - Verify ``signature`` over the ``root`` using the certificate of the node identified by ``node_id`` and ``cert``. See :py:func:`ccf.receipt.verify` for a reference implementation.
  - Check that the certificate ``cert`` of ``node_id`` used to sign the receipt is endorsed by the CCF network. See :py:func:`ccf.receipt.check_endorsement` for a reference implementation.
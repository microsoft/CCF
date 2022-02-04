Receipts
========

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
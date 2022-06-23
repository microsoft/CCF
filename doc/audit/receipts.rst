Receipts
========

In combination with a copy of the ledger, receipts are also useful for audit purposes.

Check for transaction inclusion
-------------------------------

A user having executed a transaction, fetched a receipt for it, can check for its inclusion in the ledger.
All they need to do is scan to the corresponding :term:`Transaction ID`, digest the serialised transaction, and compare it with :term:`Write Set` digest in their receipt.

For example, given the following transaction receipt:

.. code-block:: python
   :emphasize-lines: 15

    {"cert": "-----BEGIN CERTIFICATE-----\n"
            "MIIB0DCCAVWgAwIBAgIRAKut43pNWfrRFqoU3CiDwQMwCgYIKoZIzj0EAwMwFjEU\n"
            "MBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwNjIzMTI1NDMwWhcNMjIwNjI0MTI1\n"
            "NDI5WjATMREwDwYDVQQDDAhDQ0YgTm9kZTB2MBAGByqGSM49AgEGBSuBBAAiA2IA\n"
            "BEbyEIuw666ZinL2V1hRrP5MCLL2rUoM/BLyz7sECnwJKMPr8NL9zm1QawkuSjoG\n"
            "OBLBr1E+M74q0RgJFcc/r4M0NKyqgy3MG2JskXsFsZx4IlsEw1h8dAeeGoQ5zbPM\n"
            "46NqMGgwCQYDVR0TBAIwADAdBgNVHQ4EFgQUPAUVdR+vSnLqMrEMrCHbWI7XTXEw\n"
            "HwYDVR0jBBgwFoAU5947gxFF/Fe+60BAT/fxl/l2eFkwGwYDVR0RBBQwEocEfwAA\n"
            "AYcEfw55KocEfwAAAjAKBggqhkjOPQQDAwNpADBmAjEA2404WF4g1GRfcwXzB74b\n"
            "s+DRtsjalqkGVbjCTcSPWxZMRDnCgAfLp8FvjnoWFURQAjEArKvzYoZ71r+Lejdr\n"
            "ptMmANqMma9fh8eYSAwRgyM+DTlsvcjHqamnbqdp4xcQBqBb\n"
            "-----END CERTIFICATE-----\n",
    "leaf_components": {"claims_digest": "0000000000000000000000000000000000000000000000000000000000000000",
                        "commit_evidence": "ce:2.662:e423779b5314e92b79852c7b17888752d5e61e4f1ef3e79d9a06ef25cbfe2744",
                        "write_set_digest": "89145f455cb3e0854052232078989faf083237dae354180ca9942b1821f60c5d"},
    "node_id": "c5f66bbdca022af31050e104615ff0eaabd633b472bfda6650e8bee09a632ca3",
    "proof": [{"right": "3cd7b9c512371e411884917617462eacbeaf27988546a0c87fc7da89aec5b77d"},
            {"left": "6f5a6d0613488ac942af045b64782d4a14bb7466b9ad64619c7c50f335ac0ed3"},
            {"left": "d6401bf622794ae4d50b2f736cb2b6d590f42faa76cf0796ba05a57e9fb153fe"},
            {"right": "24032f6c4b57233a9ff30478b6c209ac2a7ac27c136899618fcf1d54cdcd6313"},
            {"left": "e16c5aa89b950b6ae23ff6eb297d330e7e4a239f2958d1e09d671bd8e72974ec"},
            {"left": "6058b0e8cfe37550f2feec7ae8e89905df6b7e67c2e4aff227fcb5ea0a9100cd"},
            {"left": "b582e168cd35dff37794d0f0fbac3de6dcb9271bcebc4a654f1e74be592370f3"}],
    "signature": "MGQCMBQz7qIuHxc512Prg9NjKWDYwg0i6myQ/LCm6APVYRxlLdi1gng3/CmQ6bEE2Siy7QIwRWGOVobolhrWOavwr8WPm+YqdB6LsxQhOqqU/diZ/mU9gE6NavufIKPHA6zsl46h"}

The corresponding transaction, ``2.662``, can be extracted from ledger files, and the digest compared:

.. code-block:: bash
   :emphasize-lines: 2

    $ read_ledger.py -d workspace/cpp_e2e_logging_cft_0/0.ledger/ | grep "2\.662"
        2.662 89145f455cb3e0854052232078989faf083237dae354180ca9942b1821f60c5d

Denounce an invalid recovery
----------------------------

A user having executed a number of transactions, and fetched receipts for them, can denounce a recovery that removes one or more of these transactions.
This may occur if the consortium approves a catastrophic recovery from a truncated ledger.

This user can either:

1. Query the new service for receipts at the same :term:`Transaction ID` values.  If those transactions come back as `INVALID`, because they were truncated, the signature over the old receipts is proof of truncation. If they come back as `COMMITTED` with a different root, the existence of two signatures over different roots at the same TxID is proof that a fork happened.
2. Scan the ledger, for example using the :doc:`/audit/python_library`, and find the transactions for which they have receipts. The `write_set_digest` in the receipts should match the digest of the serialised :term:`Write Set` in the ledger on disk. If it does not, the signature over the receipt is proof of a fork. See :ref:`audit/receipts:Check for transaction inclusion` for an example.
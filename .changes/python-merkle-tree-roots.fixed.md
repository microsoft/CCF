The `ccf.merkletree.MerkleTree` Python class now computes each root in time proportional to the leaves added since the previous root, preventing `ccf.ledger.LedgerValidator` from slowing down as ledgers grow.
See [Python Library](doc/audit/python_library.rst).

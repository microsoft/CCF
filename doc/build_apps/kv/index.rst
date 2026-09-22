Key-Value Store
===============

The key-value store represents the internal state of the network. It is used by applications to store data to and read from the ledger.

The pages below describe the C++ API. Rust applications use the raw-byte maps
in :doc:`../rust_api`; see :ref:`build_apps/example_rust:KV values and keys`
for serialization, confidentiality and transaction semantics.

.. toctree::
  kv_how_to
  kv_serialisation
  api
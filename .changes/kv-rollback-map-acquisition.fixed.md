Prevent C++ KV transactions from acquiring map views from different rollback branches by retrying new map acquisitions after a truncating rollback.
See [transaction semantics](doc/build_apps/kv/kv_how_to.rst#transaction-semantics).

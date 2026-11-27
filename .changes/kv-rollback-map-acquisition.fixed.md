Prevent C++ KV transactions from acquiring map views invalidated since their read version was selected, while permitting acquisition of unaffected maps.
See [transaction semantics](doc/build_apps/kv/kv_how_to.rst#transaction-semantics).

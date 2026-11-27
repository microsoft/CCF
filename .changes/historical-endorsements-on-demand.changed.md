`ccf::historical::read_only_adapter_v4` and `ccf::historical::read_write_adapter_v4` accept a `ccf::historical::ReceiptEndorsements` argument selecting the service identity endorsements attached to the receipt, and `/receipt/cose` no longer waits for or fails on endorsements it does not return.
See [Historical Queries](doc/build_apps/api.rst#historical-queries).

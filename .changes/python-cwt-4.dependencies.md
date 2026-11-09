The Python `ccf` package now requires `cwt` 4.0.0 or later and `cbor2` 6.1.5 or later.
`ccf.receipt.verify_cose` now rejects receipts with NaN CBOR map keys, and its errors for malformed receipt CBOR include the underlying `cbor2` decoding error, such as `Duplicate map key`.

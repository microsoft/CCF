Public C++ header components no longer form dependency cycles, so applications that obtained typed KV maps indirectly through headers such as `ccf/tx.h` or `ccf/crypto/sha256_hash.h` may need to include `ccf/service/map.h` or `ccf/kv/map.h` directly.
Applications can now include `ccf/research/create_tx_claims_digest.h` using only installed headers.

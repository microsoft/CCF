`ccf::NetworkIdentitySubsystemInterface` fetches and validates the endorsement chain of the PQ service identities with the classical one, failing identity history fetching if either is inconsistent, and serves it and the trusted ML-DSA service keys with `get_cose_endorsements_chain_pq(seqno)`, `get_trusted_identity_for_pq(seqno)` and `get_trusted_keys_pq()`.
Identity history fetching also validates the self-endorsement at which the classical chain ends, and fails if it is inconsistent with the chain.
See the [C++ API reference](doc/build_apps/api.rst#network-identity).

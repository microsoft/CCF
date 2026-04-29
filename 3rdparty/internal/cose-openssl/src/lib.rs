mod cbor;
mod cose;
mod ossl_wrappers;
mod sign;
mod verify;

pub use cbor::CborValue;
pub use cose::{cose_sign1, cose_verify1};
pub use ossl_wrappers::{EvpKey, KeyType, WhichEC, WhichRSA};

#[cfg(feature = "pqc")]
pub use ossl_wrappers::WhichMLDSA;

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native C ABI exposing SNP, COSE, and CACI verification.
//!
//! See `README.md` in this directory for build/link instructions and worked
//! SNP/CACI examples.
//!
//! See `ffi/tests/c-consumer` for the CMake-built consumer test suite that
//! links this ABI exactly as an external C consumer would.

// The CBOR ABI needs no crypto backend, so it is compiled whenever the crate
// targets C consumers at all.
pub(crate) mod cbor;
#[cfg(test)]
mod cbor_tests;

#[cfg(sync_crypto)]
pub(crate) mod caci;
#[cfg(sync_crypto)]
pub(crate) mod cose;
#[cfg(sync_crypto)]
pub(crate) mod snp;
#[cfg(sync_crypto)]
pub(crate) mod utils;

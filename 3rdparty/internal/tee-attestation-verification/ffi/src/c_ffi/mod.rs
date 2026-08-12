// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native C ABI exposing SNP, COSE, and CACI verification.
//!
//! See `README.md` in this directory for build/link instructions and worked
//! SNP/CACI examples.
//!
//! See `ffi/tests/c-consumer` for the CMake-built consumer test suite that
//! links this ABI exactly as an external C consumer would.

pub(crate) mod caci;
pub(crate) mod cose;
pub(crate) mod snp;
pub(crate) mod utils;

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AMD SEV-SNP attestation report types and verification APIs.

pub(crate) mod model;
pub mod report;
pub(crate) mod utils;
pub mod verify;

pub use model::{Cpuid, Generation};

/// Number of AMD endorsement certificates expected in `[vcek, ask, ark]` order.
pub const AMD_ENDORSEMENT_COUNT: usize = 3;

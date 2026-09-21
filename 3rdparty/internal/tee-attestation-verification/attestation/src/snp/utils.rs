// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// SEV-SNP OID extensions for VCEK certificate verification
/// These OIDs are used to extract TCB values from X.509 certificate extensions
pub(crate) enum Oid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
    Fmc,
}

impl Oid {
    pub fn as_str(&self) -> &'static str {
        match self {
            Oid::BootLoader => "1.3.6.1.4.1.3704.1.3.1",
            Oid::Tee => "1.3.6.1.4.1.3704.1.3.2",
            Oid::Snp => "1.3.6.1.4.1.3704.1.3.3",
            Oid::Ucode => "1.3.6.1.4.1.3704.1.3.8",
            Oid::HwId => "1.3.6.1.4.1.3704.1.4",
            Oid::Fmc => "1.3.6.1.4.1.3704.1.3.9",
        }
    }
}

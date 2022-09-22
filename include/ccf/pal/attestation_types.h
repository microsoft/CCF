// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"

#  include <array>
#  include <vector>

namespace ccf::pal::attestation
{
    enum class Format
    {
        oe_sgx_v1 = 0,
        insecure_virtual = 1,
        amd_sev_snp_v1 = 2
    };

    DECLARE_JSON_ENUM(
        Format,
        {{Format::oe_sgx_v1, "OE_SGX_v1"},
        {Format::insecure_virtual, "Insecure_Virtual"},
        {Format::amd_sev_snp_v1, "AMD_SEV_SNP_v1"}});

    using RawReport = std::vector<uint8_t>;

    struct Report {
        Format format;
        RawReport raw;
    };

    using Endorsements = std::vector<uint8_t>;

    enum class VerificationState
    {
        Unverified = 0,
        Verified = 1,
        Failed = 2
    };

    struct Attestation {
        Report report;
        Endorsements endorsements;
        VerificationState state;
    };

    inline void to_json(nlohmann::json& j, const Attestation& attestation)
    {
        j["format"] = attestation.report.format;
        j["quote"] = attestation.report.raw;
        j["endorsements"] = attestation.endorsements;
    }

    inline void from_json(const nlohmann::json& j, Attestation& attestation)
    {
        attestation = Attestation{
            .report = Report{
                .format = j["format"],
                .raw = j["quote"]
            },
            .endorsements = j["endorsements"]
        };
    }

    // TODO: Put this into the platform specific files
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
    using ReportData = std::array<uint8_t, 64>;
#else
    using ReportData = std::array<uint8_t, 32>;
#endif
    using MREnclave = std::array<uint8_t, 32>;
    using Measurement = std::array<uint8_t, 48>;
    using HostData = std::array<uint8_t, 32>;
    using SecurityPolicy = std::string;
}
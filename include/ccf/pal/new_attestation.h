// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/quote_info.h"
#include "ccf/crypto/sha256_hash.h"

#  include <array>
#  include <vector>

namespace ccf::pal::attestation
{
    using RawQuote = std::vector<uint8_t>;
    using Endorsements = std::vector<uint8_t>;

    struct Quote {
        QuoteFormat format;
        std::vector<uint8_t> raw;
    };

    enum class VerificationState
    {
        Unverified = 0,
        Verified = 1,
        Failed = 2
    };

    struct Attestation {
        Quote quote;
        Endorsements endorsements;
        VerificationState state; // TODO: Make this trustworthy
    };

    // TODO: Put this into the platform specific files
#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
    using ReportData = std::array<uint8_t, 64>;
#else
    using ReportData = std::array<uint8_t, 32>;
#endif
    ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash);

    Attestation generate(ReportData& report_data);

    bool verify(Attestation& attestation);

    ReportData get_report_data(Attestation& attestation);

    using MREnclave = std::array<uint8_t, 32>;
    std::optional<MREnclave> get_mrenclave(Attestation& attestation);

    using Measurement = std::array<uint8_t, 48>;
    std::optional<Measurement> get_measurement(Attestation& attestation);

    using HostData = std::array<uint8_t, 32>;
    std::optional<HostData> get_host_data(Attestation& attestation);

    using SecurityPolicy = std::string;
    std::optional<SecurityPolicy> get_policy(Attestation& attestation);
}
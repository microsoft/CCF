// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/pal/attestation_types.h"

#  include <array>
#  include <vector>

namespace ccf::pal::attestation
{

    ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash);

    Attestation generate(ReportData& report_data);

    bool verify(Attestation& attestation);

    ReportData get_report_data(Attestation& attestation);

    std::optional<MREnclave> get_mrenclave(Attestation& attestation);

    std::optional<Measurement> get_measurement(Attestation& attestation);

    std::optional<HostData> get_host_data(Attestation& attestation);

    std::optional<SecurityPolicy> get_policy(Attestation& attestation);

}
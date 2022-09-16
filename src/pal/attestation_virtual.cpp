// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#  include "ccf/ds/logger.h"
#  include "ccf/pal/new_attestation.h"

namespace ccf::pal::attestation {

    using ReportData = std::array<uint8_t, 64>;

    namespace insecure_virtual {

        ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash) {
            return {};
        }

        ReportData get_report_data(Attestation& attestation) {
            return {};
        }

        Attestation generate(ReportData& report_data) {
            return Attestation{
                .quote = Quote{
                    .format = QuoteFormat::insecure_virtual
                },
            };
        }

        bool verify(Attestation& attestation) {
            assert(attestation.quote.format == QuoteFormat::insecure_virtual);
            attestation.state = VerificationState::Verified;
            return true;
        }

        std::optional<MREnclave> get_mrenclave(Attestation& attestation) {
            return std::nullopt;
        }

        std::optional<Measurement> get_measurement(Attestation& attestation) {
            return std::nullopt;
        }

        std::optional<HostData> get_host_data(Attestation& attestation) {
            return std::nullopt;
        }

        std::optional<SecurityPolicy> get_policy(Attestation& attestation) {
            return std::nullopt;
        }

    }

}
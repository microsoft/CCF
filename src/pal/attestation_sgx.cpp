// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#  include "ccf/ds/logger.h"
#  include "ccf/pal/new_attestation.h"
#  include <array>
#  include <openenclave/attestation/attester.h>
#  include <openenclave/attestation/custom_claims.h>
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>

namespace ccf::pal::attestation::sgx {

    namespace constants {
        // Set of wrappers for safe memory management
        struct Claims
        {
            oe_claim_t* data = nullptr;
            size_t length = 0;

            ~Claims()
        {
            oe_free_claims(data, length);
        }
        };

        struct CustomClaims
        {
            oe_claim_t* data = nullptr;
            size_t length = 0;

            ~CustomClaims()
        {
            oe_free_custom_claims(data, length);
        }
        };

        struct SerialisedClaims
        {
            uint8_t* buffer = nullptr;
            size_t size = 0;

            ~SerialisedClaims()
        {
            oe_free_serialized_custom_claims(buffer);
        }
        };

        struct Evidence
        {
            uint8_t* buffer = NULL;
            size_t size = 0;

            ~Evidence()
        {
            oe_free_evidence(buffer);
        }
        };

        struct Endorsements
        {
            uint8_t* buffer = NULL;
            size_t size = 0;

            ~Endorsements()
        {
            oe_free_endorsements(buffer);
        }
        };

        static constexpr oe_uuid_t oe_quote_format = {OE_FORMAT_UUID_SGX_ECDSA};
        static constexpr auto report_data_claim_name = OE_CLAIM_SGX_REPORT_DATA;
    }

    std::map<std::vector<uint8_t>, MREnclave> attestation_to_mrenclave{};
    std::map<std::vector<uint8_t>, ReportData> attestation_to_report_data{};

    ReportData make_report_data(crypto::Sha256Hash& node_public_key_hash) {
        ReportData report_data{};
        std::copy(
            node_public_key_hash.h.begin(), node_public_key_hash.h.end(), report_data.begin());
        return report_data;
    }

    Attestation generate(ReportData& report_data) {

        Attestation attestation{
            .quote = Quote{
                .format = QuoteFormat::oe_sgx_v1
            },
        };

        constants::Evidence evidence;
        constants::Endorsements endorsements;
        constants::SerialisedClaims serialised_custom_claims;

        // Serialise hash of node's public key as a custom claim
        const size_t custom_claim_length = 1;
        oe_claim_t custom_claim;
        custom_claim.name = const_cast<char*>(constants::report_data_claim_name);
        custom_claim.value = report_data.data();
        custom_claim.value_size = report_data.size();

        auto rc = oe_serialize_custom_claims(
            &custom_claim,
            custom_claim_length,
            &serialised_custom_claims.buffer,
            &serialised_custom_claims.size);
        if (rc != OE_OK)
        {
        throw std::logic_error(fmt::format(
            "Could not serialise node's public key as quote custom claim: {}",
            oe_result_str(rc)));
        }

        rc = oe_get_evidence(
            &constants::oe_quote_format,
            0,
            serialised_custom_claims.buffer,
            serialised_custom_claims.size,
            nullptr,
            0,
            &evidence.buffer,
            &evidence.size,
            &endorsements.buffer,
            &endorsements.size);
        if (rc != OE_OK)
        {
        throw std::logic_error(
            fmt::format("Failed to get evidence: {}", oe_result_str(rc)));
        }

        attestation.quote.raw.assign(
            evidence.buffer, evidence.buffer + evidence.size);
        attestation.endorsements.assign(
            endorsements.buffer, endorsements.buffer + endorsements.size);

        return attestation;
    }

    bool verify(Attestation& attestation) {
        assert(attestation.quote.format == QuoteFormat::oe_sgx_v1);

        constants::Claims claims;

        auto rc = oe_verify_evidence(
            &constants::oe_quote_format,
            attestation.quote.raw.data(),
            attestation.quote.raw.size(),
            attestation.endorsements.data(),
            attestation.endorsements.size(),
            nullptr,
            0,
            &claims.data,
            &claims.length);
        if (rc != OE_OK)
        {
        throw std::logic_error(
            fmt::format("Failed to verify evidence: {}", oe_result_str(rc)));
        }

        bool unique_id_found = false;
        bool sgx_report_data_found = false;
        for (size_t i = 0; i < claims.length; i++)
        {
            auto& claim = claims.data[i];
            auto claim_name = std::string(claim.name);
            if (claim_name == OE_CLAIM_UNIQUE_ID)
            {
                MREnclave mrenclave{};
                std::copy(
                    claim.value, claim.value + claim.value_size, mrenclave.begin());
                attestation_to_mrenclave[attestation.quote.raw] = mrenclave;
                unique_id_found = true;
            }
            else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
            {
                // Find sgx report data in custom claims
                constants::CustomClaims custom_claims;
                rc = oe_deserialize_custom_claims(
                    claim.value,
                    claim.value_size,
                    &custom_claims.data,
                    &custom_claims.length);
                if (rc != OE_OK)
                {
                throw std::logic_error(fmt::format(
                    "Failed to deserialise custom claims", oe_result_str(rc)));
                }

                for (size_t j = 0; j < custom_claims.length; j++)
                {
                    auto& custom_claim = custom_claims.data[j];
                    if (std::string(custom_claim.name) == constants::report_data_claim_name)
                    {
                        ReportData report_data{};

                        if (custom_claim.value_size != report_data.size())
                        {
                            throw std::logic_error(fmt::format(
                                "Expected {} of size {}, had size {}",
                                constants::report_data_claim_name,
                                report_data.size(),
                                custom_claim.value_size));
                        }

                        std::copy(
                            custom_claim.value,
                            custom_claim.value + custom_claim.value_size,
                            report_data.begin());
                        attestation_to_report_data[attestation.quote.raw] = report_data;
                        sgx_report_data_found = true;
                        break;
                    }
                }
            }
        }

        if (!unique_id_found)
        {
        throw std::logic_error("Could not find measurement");
        }

        if (!sgx_report_data_found)
        {
        throw std::logic_error("Could not find report data");
        }

        attestation.state = VerificationState::Verified;
        return true;
    }

    void assert_verified(Attestation& attestation) {
        if (attestation.state == VerificationState::Unverified) {
            sgx::verify(attestation);
        }
        assert(attestation.state == VerificationState::Verified);
    }

    ReportData get_report_data(Attestation& attestation) {
        assert_verified(attestation);
        return attestation_to_report_data[attestation.quote.raw];
    }

    std::optional<MREnclave> get_mrenclave(Attestation& attestation) {
        assert_verified(attestation);
        return attestation_to_mrenclave[attestation.quote.raw];
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
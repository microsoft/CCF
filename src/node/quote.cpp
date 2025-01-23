// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#include "ccf/pal/attestation.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "ccf/service/tables/virtual_measurements.h"
#include "node/uvm_endorsements.h"

namespace ccf
{
  bool verify_enclave_measurement_against_uvm_endorsements(
    ccf::kv::ReadOnlyTx& tx,
    const pal::PlatformAttestationMeasurement& quote_measurement,
    const std::vector<uint8_t>& uvm_endorsements)
  {
    // Uses KV-defined roots of trust (did -> (feed, svn)) to verify the
    // UVM measurement against endorsements in the quote.
    std::vector<UVMEndorsements> uvm_roots_of_trust_from_kv;
    auto uvmes = tx.ro<SNPUVMEndorsements>(Tables::NODE_SNP_UVM_ENDORSEMENTS);
    if (uvmes)
    {
      uvmes->foreach(
        [&uvm_roots_of_trust_from_kv](
          const DID& did, const FeedToEndorsementsDataMap& endorsements_map) {
          for (const auto& [feed, data] : endorsements_map)
          {
            uvm_roots_of_trust_from_kv.push_back(
              UVMEndorsements{did, feed, data.svn});
          }
          return true;
        });
    }

    try
    {
      auto uvm_endorsements_data = verify_uvm_endorsements(
        uvm_endorsements, quote_measurement, uvm_roots_of_trust_from_kv);
      return true;
    }
    catch (const std::logic_error& e)
    {
      LOG_FAIL_FMT("Failed to verify UVM endorsements: {}", e.what());
      return false;
    }
  }

  QuoteVerificationResult verify_enclave_measurement_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const pal::PlatformAttestationMeasurement& quote_measurement,
    const QuoteFormat& quote_format,
    const std::optional<std::vector<uint8_t>>& uvm_endorsements = std::nullopt)
  {
    switch (quote_format)
    {
      case QuoteFormat::oe_sgx_v1:
      {
        if (!tx.ro<CodeIDs>(Tables::NODE_CODE_IDS)
               ->has(pal::SgxAttestationMeasurement(quote_measurement)))
        {
          return QuoteVerificationResult::FailedMeasurementNotFound;
        }
        break;
      }
      case QuoteFormat::insecure_virtual:
      {
        if (!tx.ro<VirtualMeasurements>(Tables::NODE_VIRTUAL_MEASUREMENTS)
               ->has(pal::VirtualAttestationMeasurement(
                 quote_measurement.data.begin(), quote_measurement.data.end())))
        {
          return QuoteVerificationResult::FailedMeasurementNotFound;
        }
        break;
      }
      case QuoteFormat::amd_sev_snp_v1:
      {
        // Check for UVM endorsements first as they provide better
        // serviceability.
        if (uvm_endorsements.has_value())
        {
          if (!verify_enclave_measurement_against_uvm_endorsements(
                tx, quote_measurement, uvm_endorsements.value()))
          {
            return QuoteVerificationResult::FailedUVMEndorsementsNotFound;
          }
        }
        else
        {
          if (!tx.ro<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)
                 ->has(pal::SnpAttestationMeasurement(quote_measurement)))
          {
            return QuoteVerificationResult::FailedMeasurementNotFound;
          }
        }
        break;
      }
      default:
      {
        throw std::logic_error(fmt::format(
          "Unexpected quote format {} when verifying quote against store",
          quote_format));
      }
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult verify_quoted_node_public_key(
    const std::vector<uint8_t>& expected_node_public_key,
    const ccf::crypto::Sha256Hash& quoted_hash)
  {
    if (quoted_hash != ccf::crypto::Sha256Hash(expected_node_public_key))
    {
      return QuoteVerificationResult::FailedInvalidQuotedPublicKey;
    }

    return QuoteVerificationResult::Verified;
  }

  std::optional<pal::PlatformAttestationMeasurement> AttestationProvider::
    get_measurement(const QuoteInfo& quote_info)
  {
    pal::PlatformAttestationMeasurement measurement = {};
    pal::PlatformAttestationReportData r = {};
    try
    {
      pal::verify_quote(quote_info, measurement, r);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return std::nullopt;
    }

    return measurement;
  }

  std::optional<HostData> AttestationProvider::get_host_data(
    const QuoteInfo& quote_info)
  {
    switch (quote_info.format)
    {
      case QuoteFormat::insecure_virtual:
      {
        auto j = nlohmann::json::parse(quote_info.quote);

        auto it = j.find("host_data");
        if (it != j.end())
        {
          const auto host_data = it->get<std::string>();
          return ccf::crypto::Sha256Hash::from_hex_string(host_data);
        }

        LOG_FAIL_FMT(
          "No security policy in virtual attestation from which to derive host "
          "data");
        return std::nullopt;
      }

      case QuoteFormat::amd_sev_snp_v1:
      {
        HostData digest{};
        HostData::Representation rep{};
        pal::PlatformAttestationMeasurement d = {};
        pal::PlatformAttestationReportData r = {};
        try
        {
          pal::verify_quote(quote_info, d, r);
          auto quote = *reinterpret_cast<const pal::snp::Attestation*>(
            quote_info.quote.data());
          std::copy(
            std::begin(quote.host_data),
            std::end(quote.host_data),
            rep.begin());
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
          return std::nullopt;
        }

        return digest.from_representation(rep);
      }

      default:
      {
        return std::nullopt;
      }
    }
  }

  QuoteVerificationResult verify_host_data_against_store(
    ccf::kv::ReadOnlyTx& tx, const QuoteInfo& quote_info)
  {
    if (
      quote_info.format != QuoteFormat::amd_sev_snp_v1 &&
      quote_info.format != QuoteFormat::insecure_virtual)
    {
      throw std::logic_error(
        "Attempted to verify host data for an unsupported platform");
    }

    auto host_data = AttestationProvider::get_host_data(quote_info);
    if (!host_data.has_value())
    {
      return QuoteVerificationResult::FailedHostDataDigestNotFound;
    }

    bool accepted_policy = false;

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      auto accepted_policies_table =
        tx.ro<VirtualHostDataMap>(Tables::VIRTUAL_HOST_DATA);
      accepted_policy = accepted_policies_table->contains(host_data.value());
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      auto accepted_policies_table = tx.ro<SnpHostDataMap>(Tables::HOST_DATA);
      accepted_policy = accepted_policies_table->has(host_data.value());
    }

    if (!accepted_policy)
    {
      return QuoteVerificationResult::FailedInvalidHostData;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult AttestationProvider::verify_quote_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    const std::vector<uint8_t>& expected_node_public_key_der,
    pal::PlatformAttestationMeasurement& measurement)
  {
    ccf::crypto::Sha256Hash quoted_hash;
    pal::PlatformAttestationReportData report_data;
    try
    {
      pal::verify_quote(quote_info, measurement, report_data);
      quoted_hash = report_data.to_sha256_hash();
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return QuoteVerificationResult::Failed;
    }

    auto rc = verify_host_data_against_store(tx, quote_info);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    rc = verify_enclave_measurement_against_store(
      tx, measurement, quote_info.format, quote_info.uvm_endorsements);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}
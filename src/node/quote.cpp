// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#include "ccf/pal/attestation.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "node/uvm_endorsements.h"

namespace ccf
{
  bool verify_enclave_measurement_against_uvm_endorsements(
    kv::ReadOnlyTx& tx,
    const CodeDigest& quote_measurement,
    const std::vector<uint8_t>& uvm_endorsements)
  {
    auto uvm_endorsements_data =
      verify_uvm_endorsements(uvm_endorsements, quote_measurement);
    auto uvmes = tx.ro<SNPUVMEndorsements>(Tables::NODE_SNP_UVM_ENDORSEMENTS);
    if (uvmes == nullptr)
    {
      // No recorded trusted UVM endorsements
      return false;
    }

    bool match = false;
    uvmes->foreach([&match, &uvm_endorsements_data](
                     const DID& did, const FeedToEndorsementsDataMap& value) {
      if (uvm_endorsements_data.did == did)
      {
        auto search = value.find(uvm_endorsements_data.feed);
        if (
          search != value.end() &&
          uvm_endorsements_data.svn >= search->second.svn)
        {
          match = true;
          return false;
        }
      }
      return true;
    });

    return match;
  }

  QuoteVerificationResult verify_enclave_measurement_against_store(
    kv::ReadOnlyTx& tx,
    const CodeDigest& quote_measurement,
    const QuoteFormat& quote_format,
    const std::optional<std::vector<uint8_t>>& uvm_endorsements = std::nullopt)
  {
    switch (quote_format)
    {
      case QuoteFormat::oe_sgx_v1:
      {
        pal::SgxAttestationMeasurement mr;
        // TODO: Ugly!
        std::copy(
          quote_measurement.data.begin(),
          quote_measurement.data.begin() + mr.size(),
          mr.begin());
        auto code_id = tx.ro<CodeIDs>(Tables::NODE_CODE_IDS)->get(mr);
        if (!tx.ro<CodeIDs>(Tables::NODE_CODE_IDS)->get(mr).has_value())
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
          pal::SnpAttestationMeasurement mr = quote_measurement.data;
          auto measurement =
            tx.ro<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)->get(mr);
          if (!measurement.has_value())
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
    const crypto::Sha256Hash& quoted_hash)
  {
    if (quoted_hash != crypto::Sha256Hash(expected_node_public_key))
    {
      return QuoteVerificationResult::FailedInvalidQuotedPublicKey;
    }

    return QuoteVerificationResult::Verified;
  }

  std::optional<CodeDigest> AttestationProvider::get_code_id(
    const QuoteInfo& quote_info)
  {
    CodeDigest measurement = {};
    pal::AttestationReportData r = {};
    try
    {
      pal::verify_quote(quote_info, measurement.data, r);
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
    if (access(pal::snp::DEVICE, F_OK) != 0)
    {
      return std::nullopt;
    }

    HostData digest{};
    HostData::Representation rep{};
    CodeDigest d = {};
    pal::AttestationReportData r = {};
    try
    {
      pal::verify_quote(quote_info, d.data, r);
      auto quote = *reinterpret_cast<const pal::snp::Attestation*>(
        quote_info.quote.data());
      std::copy(
        std::begin(quote.host_data), std::end(quote.host_data), rep.begin());
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return std::nullopt;
    }

    return digest.from_representation(rep);
  }

  QuoteVerificationResult verify_host_data_against_store(
    kv::ReadOnlyTx& tx, const QuoteInfo& quote_info)
  {
    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      throw std::logic_error(
        "Attempted to verify host data for an unsupported platform");
    }

    auto host_data = AttestationProvider::get_host_data(quote_info);
    if (!host_data.has_value())
    {
      return QuoteVerificationResult::FailedHostDataDigestNotFound;
    }

    auto accepted_policies_table = tx.ro<SnpHostDataMap>(Tables::HOST_DATA);
    auto accepted_policy = accepted_policies_table->get(host_data.value());
    if (!accepted_policy.has_value())
    {
      return QuoteVerificationResult::FailedInvalidHostData;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult AttestationProvider::verify_quote_against_store(
    kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    const std::vector<uint8_t>& expected_node_public_key_der,
    CodeDigest& code_digest)
  {
    crypto::Sha256Hash quoted_hash;
    pal::AttestationReportData report;
    try
    {
      pal::verify_quote(quote_info, code_digest.data, report);

      // Attestation report may be different sizes depending on the platform.
      std::copy(
        report.begin(),
        report.begin() + crypto::Sha256Hash::SIZE,
        quoted_hash.h.begin());
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return QuoteVerificationResult::Failed;
    }

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      LOG_FAIL_FMT("Skipped attestation report verification");
      return QuoteVerificationResult::Verified;
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      auto rc = verify_host_data_against_store(tx, quote_info);
      if (rc != QuoteVerificationResult::Verified)
      {
        return rc;
      }
    }

    auto rc = verify_enclave_measurement_against_store(
      tx, code_digest, quote_info.format, quote_info.uvm_endorsements);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#include "ccf/pal/attestation.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/snp_measurements.h"

namespace ccf
{
  QuoteVerificationResult verify_enclave_measurement_against_store(
    kv::ReadOnlyTx& tx,
    const CodeDigest& unique_id,
    const QuoteFormat& quote_format)
  {
    switch (quote_format)
    {
      case QuoteFormat::oe_sgx_v1:
      {
        pal::SgxAttestationMeasurement mr;
        // TODO: Ugly!
        std::copy(
          unique_id.data.begin(),
          unique_id.data.begin() + mr.size(),
          mr.begin());
        auto code_id = tx.ro<CodeIDs>(Tables::NODE_CODE_IDS)->get(mr);
        if (!code_id.has_value())
        {
          return QuoteVerificationResult::FailedCodeIdNotFound;
        }
        break;
      }
      case QuoteFormat::amd_sev_snp_v1:
      {
        pal::SnpAttestationMeasurement mr = unique_id.data;
        auto measurement =
          tx.ro<SnpMeasurements>(Tables::NODE_SNP_MEASUREMENTS)->get(mr);
        if (!measurement.has_value())
        {
          return QuoteVerificationResult::FailedCodeIdNotFound;
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
    CodeDigest unique_id = {};
    pal::AttestationReportData r = {};
    try
    {
      pal::verify_quote(quote_info, unique_id.data, r);
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify attestation report: {}", e.what());
      return std::nullopt;
    }

    return unique_id;
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
      tx, code_digest, quote_info.format);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}
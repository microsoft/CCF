// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/node/quote.h"

#include "ccf/crypto/cose.h"
#include "ccf/historical_queries_utils.h"
#include "ccf/pal/attestation.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/sev_snp_cpuid.h"
#include "ccf/service/tables/code_id.h"
#include "ccf/service/tables/jsengine.h"
#include "ccf/service/tables/node_join_policy.h"
#include "ccf/service/tables/snp_measurements.h"
#include "ccf/service/tables/tcb_verification.h"
#include "ccf/service/tables/uvm_endorsements.h"
#include "ccf/service/tables/virtual_measurements.h"
#include "crypto/cose_utils.h"
#include "ds/internal_logger.h"
#include "node/js_policy.h"
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
    std::vector<pal::UVMEndorsements> uvm_roots_of_trust_from_kv;
    auto* uvmes = tx.ro<SNPUVMEndorsements>(Tables::NODE_SNP_UVM_ENDORSEMENTS);
    if (uvmes != nullptr)
    {
      uvmes->foreach(
        [&uvm_roots_of_trust_from_kv](
          const DID& did, const FeedToEndorsementsDataMap& endorsements_map) {
          for (const auto& [feed, data] : endorsements_map)
          {
            uvm_roots_of_trust_from_kv.push_back(
              pal::UVMEndorsements{did, feed, data.svn});
          }
          return true;
        });
    }

    try
    {
      auto uvm_endorsements_data =
        verify_uvm_endorsements_against_roots_of_trust(
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

  std::optional<pal::snp::Attestation> AttestationProvider::get_snp_attestation(
    const QuoteInfo& quote_info)
  {
    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      return std::nullopt;
    }
    try
    {
      pal::PlatformAttestationMeasurement d = {};
      pal::PlatformAttestationReportData r = {};
      pal::verify_quote(quote_info, d, r);
      auto attestation = *reinterpret_cast<const pal::snp::Attestation*>(
        quote_info.quote.data());
      return attestation;
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify local attestation report: {}", e.what());
      return std::nullopt;
    }
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

        return HostData::from_representation(rep);
      }

      default:
      {
        return std::nullopt;
      }
    }
  }

  QuoteVerificationResult verify_host_data_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    std::optional<HostData>& host_data)
  {
    if (
      quote_info.format != QuoteFormat::amd_sev_snp_v1 &&
      quote_info.format != QuoteFormat::insecure_virtual)
    {
      throw std::logic_error(
        "Attempted to verify host data for an unsupported platform");
    }

    host_data = AttestationProvider::get_host_data(quote_info);
    if (!host_data.has_value())
    {
      return QuoteVerificationResult::FailedHostDataDigestNotFound;
    }

    bool accepted_policy = false;

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      auto* accepted_policies_table =
        tx.ro<VirtualHostDataMap>(Tables::VIRTUAL_HOST_DATA);
      accepted_policy = accepted_policies_table->contains(host_data.value());
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      auto* accepted_policies_table = tx.ro<SnpHostDataMap>(Tables::HOST_DATA);
      accepted_policy = accepted_policies_table->has(host_data.value());
    }

    if (!accepted_policy)
    {
      return QuoteVerificationResult::FailedInvalidHostData;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult verify_tcb_version_against_store(
    ccf::kv::ReadOnlyTx& tx, const QuoteInfo& quote_info)
  {
    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      return QuoteVerificationResult::Verified;
    }

    pal::PlatformAttestationMeasurement d = {};
    pal::PlatformAttestationReportData r = {};
    pal::verify_quote(quote_info, d, r);
    auto attestation =
      *reinterpret_cast<const pal::snp::Attestation*>(quote_info.quote.data());

    std::optional<pal::snp::TcbVersionPolicy> min_tcb_opt = std::nullopt;
    auto* h = tx.ro<SnpTcbVersionMap>(Tables::SNP_TCB_VERSIONS);
    h->foreach(
      [&min_tcb_opt, &attestation](
        const std::string& cpuid_hex, const pal::snp::TcbVersionPolicy& v) {
        auto cpuid = pal::snp::cpuid_from_hex(cpuid_hex);
        if (
          cpuid.get_family_id() == attestation.cpuid_fam_id &&
          cpuid.get_model_id() == attestation.cpuid_mod_id &&
          cpuid.stepping == attestation.cpuid_step)
        {
          min_tcb_opt = v;
          return false;
        }
        return true;
      });

    if (!min_tcb_opt.has_value())
    {
      return QuoteVerificationResult::FailedInvalidCPUID;
    }
    // CPUID of the attested cpu must now be equal to the min_tcb_opt's cpuid

    auto product_family = pal::snp::get_sev_snp_product(
      attestation.cpuid_fam_id, attestation.cpuid_mod_id);
    auto attestation_tcb_policy =
      attestation.reported_tcb.to_policy(product_family);

    if (pal::snp::TcbVersionPolicy::is_valid(
          min_tcb_opt.value(), attestation_tcb_policy))
    {
      return QuoteVerificationResult::Verified;
    }
    return QuoteVerificationResult::FailedInvalidTcbVersion;
  }

  namespace
  {
    ccf::crypto::Pem resolve_pubkey_from_x5chain_and_issuer(
      const std::vector<std::vector<uint8_t>>& x5chain,
      const std::string& issuer_did)
    {
      std::vector<std::string> pem_chain;
      pem_chain.reserve(x5chain.size());
      for (const auto& c : x5chain)
      {
        pem_chain.emplace_back(ccf::crypto::cert_der_to_pem(c).str());
      }

      auto jwk = nlohmann::json::parse(
        didx509::resolve_jwk(pem_chain, issuer_did, true));
      auto generic_jwk = jwk.get<ccf::crypto::JsonWebKey>();

      if (generic_jwk.kty != ccf::crypto::JsonWebKeyType::EC)
      {
        throw std::logic_error(fmt::format(
          "Unsupported key type ({}) for DID {}", generic_jwk.kty, issuer_did));
      }

      auto ec_jwk = jwk.get<ccf::crypto::JsonWebKeyECPublic>();
      return ccf::crypto::make_ec_public_key(ec_jwk)->public_key_pem();
    }
  }

  QuoteVerificationResult verify_code_transparent_statement(
    ccf::kv::ReadOnlyTx& tx,
    const std::vector<uint8_t>& ts_raw,
    const HostData& host_data,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem)
  {
    try
    {
      // Parse COSE_Sign1 envelope
      auto parsed = ccf::cbor::rethrow_with_msg(
        [&]() { return ccf::cbor::parse(ts_raw); },
        "Transparent statement COSE envelope");

      const auto& cose_array = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& {
          return parsed->tag_at(ccf::cbor::tag::COSE_SIGN_1);
        },
        "COSE_Sign1 tag");

      // Parse protected header bytes, then decode into structured form
      const auto& phdr_raw = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& { return cose_array->array_at(0); },
        "COSE_Sign1 protected header");
      auto phdr_cbor = ccf::cbor::rethrow_with_msg(
        [&]() { return ccf::cbor::parse(phdr_raw->as_bytes()); },
        "Parse protected header");

      auto phdr = cose::decode_sign1_protected_header(phdr_cbor);

      // Validate x5chain is present
      if (phdr.x5chain.empty())
      {
        LOG_FAIL_FMT("No certificates in transparent statement x5chain");
        return QuoteVerificationResult::FailedInvalidHostData;
      }

      // Validate issuer is present
      if (phdr.cwt.iss.empty())
      {
        LOG_FAIL_FMT("No CWT issuer in transparent statement");
        return QuoteVerificationResult::FailedInvalidHostData;
      }

      auto pubk =
        resolve_pubkey_from_x5chain_and_issuer(phdr.x5chain, phdr.cwt.iss);

      // Verify COSE_Sign1 signature
      auto verifier = ccf::crypto::make_cose_verifier_from_key(pubk);
      std::span<uint8_t> payload;
      if (!verifier->verify(ts_raw, payload))
      {
        LOG_FAIL_FMT("Transparent statement signature verification failed");
        return QuoteVerificationResult::FailedInvalidHostData;
      }

      // Verify payload matches host_data
      if (
        payload.size() != HostData::SIZE ||
        std::memcmp(payload.data(), host_data.h.data(), HostData::SIZE) != 0)
      {
        LOG_FAIL_FMT(
          "Transparent statement payload ({}) does not match host_data ({})",
          ccf::ds::to_hex(payload),
          host_data.hex_str());
        return QuoteVerificationResult::FailedInvalidHostData;
      }

      // Verify against code update policy (if one is set)
      auto* policy_table = tx.ro<CodeUpdatePolicy>(Tables::NODE_JOIN_POLICY);
      if (policy_table != nullptr)
      {
        auto policy_script = policy_table->get();
        if (policy_script.has_value())
        {
          auto violation =
            ccf::policy::apply_node_join_policy(policy_script.value(), phdr);
          if (violation.has_value())
          {
            LOG_FAIL_FMT(
              "Code update policy rejected transparent statement: {}",
              violation.value());
            return QuoteVerificationResult::FailedInvalidHostData;
          }
        }
      }

      // Extract the COSE receipt from the transparent statement's
      // unprotected header at VDP (396), and verify it against the
      // service identity (current or from a previous epoch).
      const auto& uhdr = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& { return cose_array->array_at(1); },
        "Parse transparent statement unprotected header");

      const auto& receipts_array = ccf::cbor::rethrow_with_msg(
        [&]() -> const ccf::cbor::Value& {
          return uhdr->map_at(
            ccf::cbor::make_signed(ccf::cose::header::iana::VDP));
        },
        "Parse receipts array from unprotected header");

      const auto num_receipts = receipts_array->size();
      if (num_receipts == 0)
      {
        LOG_FAIL_FMT("No receipts in transparent statement");
        return QuoteVerificationResult::FailedInvalidHostData;
      }

      if (!network_identity_subsystem)
      {
        LOG_FAIL_FMT(
          "Network identity subsystem not available for receipt "
          "verification");
        return QuoteVerificationResult::FailedInvalidHostData;
      }

      // Verify that every receipt's claims_digest matches the hash of the
      // signed statement (the COSE_Sign1 with its unprotected header
      // stripped). This binds the receipt to the specific signed content.
      auto signed_statement = ccf::cose::edit::set_unprotected_header(
        ts_raw, ccf::cose::edit::desc::Empty{});
      auto expected_claims_digest = ccf::crypto::Sha256Hash(signed_statement);

      for (size_t i = 0; i < num_receipts; ++i)
      {
        const auto& receipt_bytes = ccf::cbor::rethrow_with_msg(
          [&]() { return receipts_array->array_at(i)->as_bytes(); },
          fmt::format("Extract receipt {} from array", i));

        std::vector<uint8_t> receipt_raw(
          receipt_bytes.begin(), receipt_bytes.end());

        auto receipt_cbor = ccf::cbor::rethrow_with_msg(
          [&]() { return ccf::cbor::parse(receipt_raw); },
          fmt::format("Parse receipt {} COSE envelope", i));

        const auto& receipt_envelope = ccf::cbor::rethrow_with_msg(
          [&]() -> const ccf::cbor::Value& {
            return receipt_cbor->tag_at(ccf::cbor::tag::COSE_SIGN_1);
          },
          fmt::format("Parse receipt {} COSE_Sign1 tag", i));

        auto proofs = cose::decode_merkle_proofs(receipt_envelope);
        if (proofs.empty())
        {
          LOG_FAIL_FMT("No Merkle proofs found in receipt {}", i);
          return QuoteVerificationResult::FailedInvalidHostData;
        }

        for (const auto& proof : proofs)
        {
          if (
            proof.leaf.claims_digest.size() != ccf::crypto::Sha256Hash::SIZE ||
            std::memcmp(
              proof.leaf.claims_digest.data(),
              expected_claims_digest.h.data(),
              ccf::crypto::Sha256Hash::SIZE) != 0)
          {
            LOG_FAIL_FMT(
              "Receipt {} claims_digest ({}) does not match signed statement "
              "hash ({})",
              i,
              ccf::ds::to_hex(proof.leaf.claims_digest),
              expected_claims_digest.hex_str());
            return QuoteVerificationResult::FailedInvalidHostData;
          }
        }

        ccf::historical::verify_self_issued_receipt(
          receipt_raw, network_identity_subsystem);
      }
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Failed to verify code transparent statement: {}", e.what());
      return QuoteVerificationResult::FailedInvalidHostData;
    }

    return QuoteVerificationResult::Verified;
  }

  QuoteVerificationResult AttestationProvider::verify_quote_against_store(
    ccf::kv::ReadOnlyTx& tx,
    const QuoteInfo& quote_info,
    const std::vector<uint8_t>& expected_node_public_key_der,
    pal::PlatformAttestationMeasurement& measurement,
    const std::optional<std::vector<uint8_t>>& code_transparent_statement,
    std::shared_ptr<NetworkIdentitySubsystemInterface>
      network_identity_subsystem)
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

    std::optional<HostData> host_data{std::nullopt};
    auto rc = verify_host_data_against_store(tx, quote_info, host_data);
    if (rc == QuoteVerificationResult::FailedInvalidHostData)
    {
      if (code_transparent_statement.has_value())
      {
        if (!host_data.has_value())
        {
          // It must not happen after verify_host_data_against_store returns
          // FailedInvalidHostData, but let's handle gracefully.
          return QuoteVerificationResult::FailedHostDataDigestNotFound;
        }

        rc = verify_code_transparent_statement(
          tx,
          code_transparent_statement.value(),
          host_data.value(),
          network_identity_subsystem);
      }
    }

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

    rc = verify_tcb_version_against_store(tx, quote_info);
    if (rc != QuoteVerificationResult::Verified)
    {
      return rc;
    }

    return verify_quoted_node_public_key(
      expected_node_public_key_der, quoted_hash);
  }
}
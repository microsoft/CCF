// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"

#include <fcntl.h>
#include <functional>
#include <unistd.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include <sys/ioctl.h>
#else
#  include "ccf/pal/attestation_sgx.h"
#endif

namespace ccf::pal
{
  // Caller-supplied callback used to retrieve endorsements as specified by
  // the config argument. When called back, the quote_info argument will have
  // already been populated with the raw quote.
  using RetrieveEndorsementCallback = std::function<void(
    const QuoteInfo& quote_info,
    const snp::EndorsementEndpointsConfiguration& config)>;

  // Verifying SNP attestation report is available on all platforms as unlike
  // SGX, this does not require external dependencies (Open Enclave for SGX).
  static void verify_snp_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    if (quote_info.format != QuoteFormat::amd_sev_snp_v1)
    {
      throw std::logic_error(fmt::format(
        "Unexpected attestation report to verify for SEV-SNP: {}",
        quote_info.format));
    }

    if (quote_info.quote.size() != sizeof(snp::Attestation))
    {
      throw std::logic_error(fmt::format(
        "Input SEV-SNP attestation report is not of expected size {}: {}",
        sizeof(snp::Attestation),
        quote_info.quote.size()));
    }

    auto quote =
      *reinterpret_cast<const snp::Attestation*>(quote_info.quote.data());

    if (quote.version != snp::attestation_version)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation version is {} not expected {}",
        quote.version,
        snp::attestation_version));
    }

    if (quote.flags.signing_key != snp::attestation_flags_signing_key_vcek)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Attestation report must be signed by VCEK: {}",
        static_cast<uint8_t>(quote.flags.signing_key)));
    }

    if (quote.flags.mask_chip_key != 0)
    {
      throw std::logic_error(
        fmt::format("SEV-SNP: Mask chip key must not be set"));
    }

    report_data = SnpAttestationReportData(quote.report_data);
    measurement = SnpAttestationMeasurement(quote.measurement);

    auto certificates = crypto::split_x509_cert_bundle(std::string_view(
      reinterpret_cast<const char*>(quote_info.endorsements.data()),
      quote_info.endorsements.size()));
    if (certificates.size() != 3)
    {
      throw std::logic_error(fmt::format(
        "Expected 3 endorsement certificates but got {}", certificates.size()));
    }
    auto chip_certificate = certificates[0];
    auto sev_version_certificate = certificates[1];
    auto root_certificate = certificates[2];

    auto root_cert_verifier = crypto::make_verifier(root_certificate);

    if (
      root_cert_verifier->public_key_pem().str() !=
      snp::amd_milan_root_signing_public_key)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "the expected one {}",
        root_cert_verifier->public_key_pem().str()));
    }

    if (!root_cert_verifier->verify_certificate({&root_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The root of trust public key for this attestation was not "
        "self signed as expected");
    }

    auto chip_cert_verifier = crypto::make_verifier(chip_certificate);
    if (!chip_cert_verifier->verify_certificate(
          {&root_certificate, &sev_version_certificate}))
    {
      throw std::logic_error(
        "SEV-SNP: The chain of signatures from the root of trust to this "
        "attestation is broken");
    }

    if (quote.signature_algo != snp::SignatureAlgorithm::ecdsa_p384_sha384)
    {
      throw std::logic_error(fmt::format(
        "SEV-SNP: Unsupported signature algorithm: {} (supported: {})",
        quote.signature_algo,
        snp::SignatureAlgorithm::ecdsa_p384_sha384));
    }

    // Make ASN1 DER signature
    auto quote_signature = crypto::ecdsa_sig_from_r_s(
      quote.signature.r,
      sizeof(quote.signature.r),
      quote.signature.s,
      sizeof(quote.signature.s),
      false /* little endian */
    );

    std::span quote_without_signature{
      quote_info.quote.data(),
      quote_info.quote.size() - sizeof(quote.signature)};
    if (!chip_cert_verifier->verify(quote_without_signature, quote_signature))
    {
      throw std::logic_error(
        "SEV-SNP: Chip certificate (VCEK) did not sign this attestation");
    }

    // We should check this (although not security critical) but the guest
    // policy ABI is currently set to 0.31, although we are targeting 1.54
    // if (quote.policy.abi_major < snp::attestation_policy_abi_major)
    // {
    //   throw std::logic_error(fmt::format(
    //     "SEV-SNP: Attestation guest policy ABI major {} must be greater than
    //     " "or equal to {}", quote.policy.abi_major,
    //     snp::attestation_policy_abi_major));
    // }

    if (quote.policy.debug != 0)
    {
      throw std::logic_error(
        "SEV-SNP: SNP attestation report guest policy debugging must not be "
        "enabled");
    }

    if (quote.policy.migrate_ma != 0)
    {
      throw std::logic_error("SEV-SNP: Migration agents must not be enabled");
    }

    // Only has value when endorsements are retrieved from environment
    if (quote_info.endorsed_tcb.has_value())
    {
      const auto& endorsed_tcb = quote_info.endorsed_tcb.value();
      auto raw_tcb = ds::from_hex(quote_info.endorsed_tcb.value());

      if (raw_tcb.size() != sizeof(snp::TcbVersion))
      {
        throw std::logic_error(fmt::format(
          "SEV-SNP: TCB of size {}, expected {}",
          raw_tcb.size(),
          sizeof(snp::TcbVersion)));
      }

      snp::TcbVersion tcb = *reinterpret_cast<snp::TcbVersion*>(raw_tcb.data());
      if (tcb != quote.reported_tcb)
      {
        auto* reported_tcb = reinterpret_cast<uint8_t*>(&quote.reported_tcb);
        throw std::logic_error(fmt::format(
          "SEV-SNP: endorsed TCB {} does not match reported TCB {}",
          endorsed_tcb,
          ds::to_hex(
            {reported_tcb, reported_tcb + sizeof(quote.reported_tcb)})));
      }
    }
  }

#if defined(PLATFORM_VIRTUAL)

  static void generate_quote(
    PlatformAttestationReportData& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    endorsement_cb(
      {
        .format = QuoteFormat::insecure_virtual,
      },
      {});
  }

#elif defined(PLATFORM_SNP)

  static void generate_quote(
    PlatformAttestationReportData& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    QuoteInfo node_quote_info = {};

    node_quote_info.format = QuoteFormat::amd_sev_snp_v1;
    int fd = open(snp::DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
      throw std::logic_error(fmt::format("Failed to open \"{}\"", snp::DEVICE));
    }

    snp::AttestationReq req = {};
    snp::AttestationResp resp = {};

    // Arbitrary report data
    memcpy(
      req.report_data, report_data.data(), snp_attestation_report_data_size);

    // Documented at
    // https://www.kernel.org/doc/html/latest/virt/coco/sev-guest.html
    snp::GuestRequest payload = {
      .req_msg_type = snp::MSG_REPORT_REQ,
      .rsp_msg_type = snp::MSG_REPORT_RSP,
      .msg_version = 1,
      .request_len = sizeof(req),
      .request_uaddr = reinterpret_cast<uint64_t>(&req),
      .response_len = sizeof(resp),
      .response_uaddr = reinterpret_cast<uint64_t>(&resp),
      .error = 0};

    int rc = ioctl(fd, SEV_SNP_GUEST_MSG_REPORT, &payload);
    if (rc < 0)
    {
      CCF_APP_FAIL("IOCTL call failed: {}", strerror(errno));
      CCF_APP_FAIL("Payload error: {}", payload.error);
      throw std::logic_error("Failed to issue ioctl SEV_SNP_GUEST_MSG_REPORT");
    }

    auto quote = &resp.report;
    auto quote_bytes = reinterpret_cast<uint8_t*>(&resp.report);
    node_quote_info.quote.assign(quote_bytes, quote_bytes + resp.report_size);

    if (endorsement_cb != nullptr)
    {
      endorsement_cb(
        node_quote_info,
        snp::make_endorsement_endpoint_configuration(
          *quote, endorsements_servers));
    }
  }
#endif

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  static void verify_quote(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    auto is_sev_snp = access(snp::DEVICE, F_OK) == 0;

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      if (is_sev_snp)
      {
        throw std::logic_error(
          "Cannot verify virtual attestation report if node is SEV-SNP");
      }
      // For now, virtual resembles SGX (mostly for historical reasons)
      measurement = SgxAttestationMeasurement();
      report_data = SgxAttestationReportData();
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      if (!is_sev_snp)
      {
        throw std::logic_error(
          "Cannot verify SEV-SNP attestation report if node is virtual");
      }

      verify_snp_attestation_report(quote_info, measurement, report_data);
    }
    else
    {
      if (is_sev_snp)
      {
        throw std::logic_error(
          "Cannot verify SGX attestation report if node is SEV-SNP");
      }
      else
      {
        throw std::logic_error(
          "Cannot verify SGX attestation report if node is virtual");
      }
    }
  }

#else // SGX

  static void generate_quote(
    PlatformAttestationReportData& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    QuoteInfo node_quote_info = {};
    node_quote_info.format = QuoteFormat::oe_sgx_v1;

    sgx::Evidence evidence;
    sgx::Endorsements endorsements;
    sgx::SerialisedClaims serialised_custom_claims;

    const size_t custom_claim_length = 1;
    oe_claim_t custom_claim;
    custom_claim.name = const_cast<char*>(sgx::report_data_claim_name);
    custom_claim.value = report_data.data.data();
    custom_claim.value_size = report_data.data.size();

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
      &sgx::oe_quote_format,
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

    node_quote_info.quote.assign(
      evidence.buffer, evidence.buffer + evidence.size);
    node_quote_info.endorsements.assign(
      endorsements.buffer, endorsements.buffer + endorsements.size);

    if (endorsement_cb != nullptr)
    {
      endorsement_cb(node_quote_info, {});
    }
  }

  static void verify_quote(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data)
  {
    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      throw std::logic_error(fmt::format(
        "Cannot verify virtual insecure attestation report on SGX platform"));
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      verify_snp_attestation_report(quote_info, measurement, report_data);
      return;
    }

    sgx::Claims claims;

    auto rc = oe_verify_evidence(
      &sgx::oe_quote_format,
      quote_info.quote.data(),
      quote_info.quote.size(),
      quote_info.endorsements.data(),
      quote_info.endorsements.size(),
      nullptr,
      0,
      &claims.data,
      &claims.length);
    if (rc != OE_OK)
    {
      throw std::logic_error(fmt::format(
        "Failed to verify evidence in SGX attestation report: {}",
        oe_result_str(rc)));
    }

    std::optional<SgxAttestationMeasurement> claim_measurement = std::nullopt;
    std::optional<SgxAttestationReportData> custom_claim_report_data =
      std::nullopt;
    for (size_t i = 0; i < claims.length; i++)
    {
      auto& claim = claims.data[i];
      auto claim_name = std::string(claim.name);
      if (claim_name == OE_CLAIM_UNIQUE_ID)
      {
        if (claim.value_size != SgxAttestationMeasurement::size())
        {
          throw std::logic_error(
            fmt::format("SGX measurement claim is not of expected size"));
        }

        claim_measurement =
          SgxAttestationMeasurement({claim.value, claim.value_size});
      }
      else if (claim_name == OE_CLAIM_CUSTOM_CLAIMS_BUFFER)
      {
        // Find sgx report data in custom claims
        sgx::CustomClaims custom_claims;
        rc = oe_deserialize_custom_claims(
          claim.value,
          claim.value_size,
          &custom_claims.data,
          &custom_claims.length);
        if (rc != OE_OK)
        {
          throw std::logic_error(fmt::format(
            "Failed to deserialise custom claims in SGX attestation report",
            oe_result_str(rc)));
        }

        for (size_t j = 0; j < custom_claims.length; j++)
        {
          auto& custom_claim = custom_claims.data[j];
          if (std::string(custom_claim.name) == sgx::report_data_claim_name)
          {
            if (custom_claim.value_size != SgxAttestationReportData::size())
            {
              throw std::logic_error(fmt::format(
                "Expected claim {} of size {}, had size {}",
                sgx::report_data_claim_name,
                SgxAttestationReportData::size(),
                custom_claim.value_size));
            }

            custom_claim_report_data = SgxAttestationReportData(
              {custom_claim.value, custom_claim.value_size});

            break;
          }
        }
      }
    }

    if (!claim_measurement.has_value())
    {
      throw std::logic_error(
        "Could not find measurement in SGX attestation report");
    }

    if (!custom_claim_report_data.has_value())
    {
      throw std::logic_error(
        "Could not find report data in SGX attestation report");
    }

    measurement = claim_measurement.value();
    report_data = custom_claim_report_data.value();
  }

#endif
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation_sev_snp.h"

#include <fcntl.h>
#include <functional>
#include <unistd.h>

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)
#  include "ccf/crypto/pem.h"
#  include "ccf/crypto/verifier.h"
#  include "crypto/ecdsa.h"

#  include <sys/ioctl.h>
#else
#  include "ccf/pal/attestation_sgx.h"
#endif

#include <ravl/oe_impl.h>
#include <ravl/options.h>
#include <ravl/sev_snp_impl.h>

namespace ccf::pal
{
  // Caller-supplied callback used to retrieve endorsements as specified by
  // the config argument. When called back, the quote_info argument will have
  // already been populated with the raw quote.
  using RetrieveEndorsementCallback = std::function<void(
    const QuoteInfo& quote_info,
    const snp::EndorsementEndpointsConfiguration& config)>;

#if !defined(INSIDE_ENCLAVE) || defined(VIRTUAL_ENCLAVE)

  static void generate_quote(
    attestation_report_data& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    QuoteInfo node_quote_info = {};
    auto is_sev_snp = access(snp::DEVICE, F_OK) == 0;

    // If there is no SEV-SNP device, assume we are using insecure virtual
    // quotes
    if (!is_sev_snp)
    {
      node_quote_info.format = QuoteFormat::insecure_virtual;
      endorsement_cb(node_quote_info, {});
      return;
    }

    node_quote_info.format = QuoteFormat::amd_sev_snp_v1;
    int fd = open(snp::DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
      throw std::logic_error(fmt::format("Failed to open \"{}\"", snp::DEVICE));
    }

    snp::AttestationReq req = {};
    snp::AttestationResp resp = {};

    // Arbitrary report data
    memcpy(req.report_data, report_data.data(), attestation_report_data_size);

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

  static void verify_quote(
    const QuoteInfo& quote_info,
    attestation_measurement& unique_id,
    attestation_report_data& report_data)
  {
    auto is_sev_snp = access(snp::DEVICE, F_OK) == 0;

    if (quote_info.format == QuoteFormat::insecure_virtual)
    {
      if (is_sev_snp)
      {
        throw std::logic_error(
          "Cannot verify virtual quote if node is SEV-SNP");
      }
      unique_id = {};
      report_data = {};
    }
    else if (quote_info.format == QuoteFormat::amd_sev_snp_v1)
    {
      if (!is_sev_snp)
      {
        throw std::logic_error(
          "Cannot verify SEV-SNP quote if node is virtual");
      }

      try
      {
        using namespace ravl;
        auto attestation = std::make_shared<sev_snp::Attestation>(
          quote_info.quote, quote_info.endorsements);
        auto claims = attestation->verify(Options(), {});
        auto sev_snp_claims = Claims::get<sev_snp::Claims>(claims);

        report_data = sev_snp_claims->report_data;
        unique_id = sev_snp_claims->measurement;
      }
      catch (const std::exception& ex)
      {
        throw std::logic_error(
          fmt::format("Failed to verify evidence: {}", ex.what()));
      }
    }
    else
    {
      if (is_sev_snp)
      {
        throw std::logic_error(fmt::format(
          "Cannot verify non SEV-SNP attestation report: {}",
          quote_info.format));
      }
      else
      {
        throw std::logic_error(
          "Cannot verify real attestation report on virtual build");
      }
    }
  }

#else

  static void generate_quote(
    attestation_report_data& report_data,
    RetrieveEndorsementCallback endorsement_cb,
    const snp::EndorsementsServers& endorsements_servers = {})
  {
    QuoteInfo node_quote_info = {};
    node_quote_info.format = QuoteFormat::oe_sgx_v1;

    sgx::Evidence evidence;
    sgx::Endorsements endorsements;
    sgx::SerialisedClaims serialised_custom_claims;

    // Serialise hash of node's public key as a custom claim
    const size_t custom_claim_length = 1;
    oe_claim_t custom_claim;
    custom_claim.name = const_cast<char*>(sgx::report_data_claim_name);
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
    attestation_measurement& unique_id,
    attestation_report_data& report_data)
  {
    if (quote_info.format != QuoteFormat::oe_sgx_v1)
    {
      throw std::logic_error(
        fmt::format("Cannot verify non OE SGX report: {}", quote_info.format));
    }

    try
    {
      using namespace ravl;
      auto attestation = std::make_shared<oe::Attestation>(
        quote_info.quote, quote_info.endorsements);
      auto claims = attestation->verify();
      auto oe_claims = Claims::get<oe::Claims>(claims);

      unique_id = oe_claims->sgx_claims->report_body.mr_enclave;

      const auto& claimed_rdata =
        oe_claims->custom_claims.at(sgx::report_data_claim_name);

      if (claimed_rdata.size() != report_data.size())
      {
        throw std::logic_error(fmt::format(
          "Expected {} of size {}, had size {}",
          sgx::report_data_claim_name,
          report_data.size(),
          claimed_rdata.size()));
      }

      std::copy(
        claimed_rdata.begin(), claimed_rdata.end(), report_data.begin());
    }
    catch (const std::exception& ex)
    {
      throw std::logic_error(
        fmt::format("Failed to verify evidence: {}", ex.what()));
    }

    if (unique_id.empty())
    {
      throw std::logic_error("Could not find measurement");
    }

    if (report_data.empty())
    {
      throw std::logic_error("Could not find report data");
    }
  }

#endif
}
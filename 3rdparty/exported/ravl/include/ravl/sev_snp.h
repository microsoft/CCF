// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "attestation.h"

#include <array>
#include <memory>
#include <optional>

namespace ravl
{
  class HTTPClient;

  namespace sev_snp
  {
    struct Endorsements
    {
      std::string root_ca_certificate;
      std::string vcek_certificate_chain;
      std::optional<std::string> vcek_issuer_chain_crl;
    };

    class Claims : public ravl::Claims
    {
    public:
      Claims() : ravl::Claims(Source::SEV_SNP) {}

      virtual ~Claims() = default;

      struct TCBVersion
      {
        uint8_t boot_loader;
        uint8_t tee;
        uint8_t snp;
        uint8_t microcode;
      };

      struct Signature
      {
        std::array<uint8_t, 72> r;
        std::array<uint8_t, 72> s;
      };

      uint32_t version;
      uint32_t guest_svn;
      uint64_t policy;
      std::array<uint8_t, 16> family_id;
      std::array<uint8_t, 16> image_id;
      uint32_t vmpl;
      uint32_t signature_algo;
      TCBVersion platform_version;
      uint64_t platform_info;
      uint32_t flags;
      std::array<uint8_t, 64> report_data;
      std::array<uint8_t, 48> measurement;
      std::array<uint8_t, 32> host_data;
      std::array<uint8_t, 48> id_key_digest;
      std::array<uint8_t, 48> author_key_digest;
      std::array<uint8_t, 32> report_id;
      std::array<uint8_t, 32> report_id_ma;
      TCBVersion reported_tcb;
      std::array<uint8_t, 64> chip_id;
      TCBVersion committed_tcb;
      uint8_t current_minor;
      uint8_t current_build;
      uint8_t current_major;
      uint8_t committed_build;
      uint8_t committed_minor;
      uint8_t committed_major;
      TCBVersion launch_tcb;
      Signature signature;

      Endorsements endorsements;
    };

    class Attestation : public ravl::Attestation
    {
    public:
      Attestation(
        const std::vector<uint8_t>& evidence,
        const std::vector<uint8_t>& endorsements) :
        ravl::Attestation(Source::SEV_SNP, evidence, endorsements)
      {}

      Attestation(
        const std::vector<uint8_t>& evidence, const Endorsements& endorsements);

      virtual std::optional<HTTPRequests> prepare_endorsements(
        const Options& options) const override;

      virtual std::shared_ptr<ravl::Claims> verify(
        const Options& options = {},
        const std::optional<HTTPResponses>& http_responses = {}) const override;
    };
  }
}

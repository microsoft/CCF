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

  namespace sgx
  {
    struct Endorsements
    {
      uint16_t major_version;
      uint16_t minor_version;
      uint32_t tee_type;

      // All in PEM format
      std::string root_ca;
      std::string pck_crl_issuer_chain;
      std::string root_ca_crl;
      std::string pck_crl;
      std::string tcb_info_issuer_chain;
      std::string tcb_info;
      std::string qe_identity_issuer_chain;
      std::string qe_identity;
    };

    class Claims : public ravl::Claims
    {
    public:
      Claims() : ravl::Claims(Source::SGX) {}

      virtual ~Claims() = default;

      struct ReportAttributes
      {
        uint64_t flags;
        uint64_t xfrm;
      };

      struct ReportBody
      {
        std::array<uint8_t, 16> cpu_svn;
        uint32_t misc_select;
        std::array<uint8_t, 16> isv_ext_prod_id;
        ReportAttributes attributes;
        std::array<uint8_t, 32> mr_enclave;
        std::array<uint8_t, 32> mr_signer;
        std::array<uint8_t, 64> config_id;
        uint16_t isv_prod_id;
        uint16_t isv_svn;
        uint16_t config_svn;
        std::array<uint8_t, 16> isv_family_id;
        std::array<uint8_t, 64> report_data;
      };

      uint16_t version;
      uint16_t sign_type;
      std::array<uint8_t, 4> epid_group_id;
      uint16_t qe_svn;
      uint16_t pce_svn;
      uint32_t xeid;
      std::array<uint8_t, 32> basename;
      ReportBody report_body;

      struct
      {
        std::array<uint8_t, 32 * 2> signature;
        std::array<uint8_t, 32 * 2> attest_pub_key;
        ReportBody qe_report;
        std::array<uint8_t, 32 * 2> qe_report_sig;
        std::vector<uint8_t> auth_data;
      } signature_data;

      Endorsements endorsements;
    };

    class Attestation : public ravl::Attestation
    {
    public:
      Attestation(
        const std::vector<uint8_t>& evidence,
        const std::vector<uint8_t>& endorsements) :
        ravl::Attestation(Source::SGX, evidence, endorsements)
      {}

      virtual ~Attestation() = default;

      virtual std::optional<HTTPRequests> prepare_endorsements(
        const Options& options) const override;

      virtual std::shared_ptr<ravl::Claims> verify(
        const Options& options = {},
        const std::optional<HTTPResponses>& http_responses = {}) const override;
    };
  }
}

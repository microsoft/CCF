// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "sgx.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ravl
{
  class HTTPClient;

  namespace oe
  {
    class Claims : public ravl::Claims
    {
    public:
      Claims() : ravl::Claims(Source::OPEN_ENCLAVE) {}

      virtual ~Claims() = default;

      std::shared_ptr<sgx::Claims> sgx_claims;
      std::map<std::string, std::vector<uint8_t>> custom_claims;
    };

    class Attestation : public ravl::Attestation
    {
    public:
      Attestation(
        const std::vector<uint8_t>& evidence,
        const std::vector<uint8_t>& endorsements) :
        ravl::Attestation(Source::OPEN_ENCLAVE, evidence, endorsements)
      {}

      virtual std::optional<HTTPRequests> prepare_endorsements(
        const Options& options) const override;

      virtual std::shared_ptr<ravl::Claims> verify(
        const Options& options = {},
        const std::optional<HTTPResponses>& http_responses = {}) const override;

    protected:
      mutable std::shared_ptr<ravl::Attestation> sgx_attestation;
      mutable std::vector<uint8_t> custom_claims;
    };
  }
}

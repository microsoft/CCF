// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "http_client.h"
#include "options.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ravl
{
  enum class Source : uint8_t
  {
    SGX = 0,
    SEV_SNP = 1,
    OPEN_ENCLAVE = 2,
    UNKNOWN = UINT8_MAX
  };

  class Claims
  {
  public:
    Claims() : source(Source::UNKNOWN) {}
    Claims(const Claims&) = default;
    Claims(Claims&&) = default;

    Claims(Source source) : source(source) {}

    virtual ~Claims() = default;

    Source source;

    Claims& operator=(const Claims&) = default;

    /// Function to up-cast generic claims
    template <typename T>
    static std::shared_ptr<T> get(std::shared_ptr<ravl::Claims>& claims);
  };

  class Attestation
  {
  public:
    Attestation() : source(Source::UNKNOWN) {}

    Attestation(
      Source source,
      const std::vector<uint8_t>& evidence,
      const std::vector<uint8_t>& endorsements);

    Attestation(const Attestation&) = default;
    Attestation(Attestation&&) = default;

    virtual ~Attestation() {}

    Source source;
    std::vector<uint8_t> evidence;
    std::vector<uint8_t> endorsements;

    /// Function to prepare network requests for endorsements
    virtual std::optional<HTTPRequests> prepare_endorsements(
      const Options& options) const = 0;

    /// Function to verify the attestation (with all endorsements present either
    /// in the attestation object or in the url_response_set).
    virtual std::shared_ptr<Claims> verify(
      const Options& options,
      const std::optional<HTTPResponses>& http_response_set) const = 0;

    operator std::string() const;

    Attestation& operator=(const Attestation& other) = default;
  };

  std::shared_ptr<Attestation> parse_attestation(
    const std::string& json_string);
}

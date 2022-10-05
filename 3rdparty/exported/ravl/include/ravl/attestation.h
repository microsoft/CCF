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
  /// Source enumeration
  enum class Source : uint8_t
  {
    SGX = 0,
    SEV_SNP = 1,
    OPEN_ENCLAVE = 2,
    UNKNOWN = UINT8_MAX
  };

  std::string to_string(Source src);

  /// Claims class
  class Claims
  {
  public:
    /// Constructor
    Claims() : source(Source::UNKNOWN) {}

    /// Constructor
    Claims(Source source) : source(source) {}

    /// Copy constructor
    Claims(const Claims&) = default;

    /// Move constructor
    Claims(Claims&&) = default;

    /// Destructor
    virtual ~Claims() = default;

    /// Source (platform) of the claims
    Source source;

    /// Assignment operator
    Claims& operator=(const Claims&) = default;

    /// Function to up-cast generic claims
    template <typename T>
    static std::shared_ptr<T> get(std::shared_ptr<ravl::Claims>& claims);
  };

  /// Attestation class
  class Attestation
  {
  public:
    /// Constructor
    Attestation() : source(Source::UNKNOWN) {}

    /// Constructor
    Attestation(
      Source source,
      const std::vector<uint8_t>& evidence,
      const std::vector<uint8_t>& endorsements) :
      source(source), evidence(evidence), endorsements(endorsements)
    {}

    /// Copy constructor
    Attestation(const Attestation&) = default;

    /// Move constructor
    Attestation(Attestation&&) = default;

    /// Destructor
    virtual ~Attestation() {}

    /// Source (platform) of the attestation
    Source source;

    /// Evidence
    std::vector<uint8_t> evidence;

    /// Endorsements
    std::vector<uint8_t> endorsements;

    /// Function to prepare network requests for endorsements
    virtual std::optional<HTTPRequests> prepare_endorsements(
      const Options& options) const = 0;

    /// Function to verify the attestation (with all endorsements present either
    /// in the attestation object or in the http_responses).
    virtual std::shared_ptr<Claims> verify(
      const Options& options = {},
      const std::optional<HTTPResponses>& http_responses = {}) const = 0;

    /// String representation
    operator std::string() const;

    /// Assignment operator
    Attestation& operator=(const Attestation& other) = default;
  };

  // Parse a JSON-encoded attestation
  std::shared_ptr<Attestation> parse_attestation(
    const std::string& json_string);
}

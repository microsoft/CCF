// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/node_subsystem_interface.h"

#include <exception>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  struct NetworkIdentity;

  /// A single raw COSE endorsement, stored as an opaque byte vector.
  using RawCoseEndorsement = std::vector<uint8_t>;
  /// An ordered chain of raw COSE endorsements.
  using CoseEndorsementsChain = std::vector<RawCoseEndorsement>;

  /// Status of the network identity endorsement fetching process.
  enum class FetchStatus : uint8_t
  {
    Retry, ///< Fetching should be retried
    Done, ///< Fetching completed successfully
    Failed ///< Fetching failed
  };

  /// Map from sequence number to EC public key, representing the trusted
  /// network identity keys over the history of the service.
  using TrustedKeys = std::map<ccf::SeqNo, ccf::crypto::ECPublicKeyPtr>;

  /// Exception thrown when identity data is requested before the
  /// asynchronous identity-history-fetching process has completed.
  struct IdentityHistoryNotFetched : public std::exception
  {
    std::string msg;

    IdentityHistoryNotFetched(std::string msg) : msg(std::move(msg)) {}

    [[nodiscard]] const char* what() const noexcept override
    {
      return msg.c_str();
    }
  };

  /// Interface for accessing the network identity subsystem, which manages
  /// the service's cryptographic identity and its historical trusted keys.
  class NetworkIdentitySubsystemInterface : public ccf::AbstractNodeSubSystem
  {
  public:
    ~NetworkIdentitySubsystemInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "NetworkIdentity";
    }

    /// Returns a reference to the current network identity.
    virtual const std::unique_ptr<NetworkIdentity>& get() = 0;

    /// Returns the current status of endorsement fetching.
    [[nodiscard]] virtual FetchStatus endorsements_fetching_status() const = 0;

    /// Returns the COSE endorsements chain for the given sequence number,
    /// or std::nullopt if the chain is not available for the given sequence
    /// number.
    ///
    /// @throws IdentityHistoryNotFetched if identity history fetching has not
    /// completed.
    [[nodiscard]] virtual std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const = 0;

    /// Returns the trusted EC public key that was active at the given
    /// sequence number, or nullptr if the sequence number precedes the
    /// earliest known trusted key.
    ///
    /// @throws IdentityHistoryNotFetched if identity history fetching has not
    /// completed.
    /// @throws std::logic_error if no trusted keys have been fetched, or if
    /// internal key resolution is inconsistent.
    [[nodiscard]] virtual ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const = 0;

    /// Returns all trusted network identity keys as a map from sequence
    /// number to EC public key.
    ///
    /// @throws IdentityHistoryNotFetched if identity history fetching has not
    /// completed.
    [[nodiscard]] virtual TrustedKeys get_trusted_keys() const = 0;
  };
}

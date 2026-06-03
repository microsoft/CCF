// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/tx_id.h"

#include <map>
#include <optional>
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
    Done, ///< Fetching trusted identities completed successfully
    Partial, ///< Chain is still being built or fetching attempts were
             ///< exhausted (e.g. ledger files missing). Readers see the
             ///< validated subset; @ref trigger_extension can request
             ///< more.
    Failed ///< Fetching failed with error and cannot be resumed
  };

  /// Map from sequence number to EC public key, representing the trusted
  /// network identity keys over the history of the service.
  using TrustedKeys = std::map<ccf::SeqNo, ccf::crypto::ECPublicKeyPtr>;

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

    /// Returns the current status of endorsement fetching. Callers
    /// should check this before acting on a nullopt/nullptr/empty
    /// reader result: in @ref FetchStatus::Partial more data may
    /// arrive via @ref trigger_extension; in @ref FetchStatus::Failed
    /// the fetch is unrecoverable.
    [[nodiscard]] virtual FetchStatus endorsements_fetching_status() const = 0;

    /// Schedule a fresh attempt to fetch the next missing predecessor
    /// endorsement. No-op outside @ref FetchStatus::Partial. Thread-safe
    /// and idempotent: concurrent callers trigger at most one cycle.
    virtual void trigger_extension() = 0;

    /// Returns the COSE endorsements chain for the given sequence number,
    /// or std::nullopt if the chain does not yet reach back to the
    /// requested seqno (see @ref trigger_extension).
    [[nodiscard]] virtual std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const = 0;

    /// Returns the trusted EC public key that was active at the given
    /// sequence number, or nullptr if the sequence number predates the
    /// earliest known trusted key (see @ref trigger_extension).
    [[nodiscard]] virtual ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const = 0;

    /// Returns all trusted network identity keys as a map from sequence
    /// number to EC public key. In @ref FetchStatus::Partial older epochs
    /// may be missing — see @ref trigger_extension.
    [[nodiscard]] virtual TrustedKeys get_trusted_keys() const = 0;
  };
}

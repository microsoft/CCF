// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/tx_id.h"

#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  struct NetworkIdentity;

  using RawCoseEndorsement = std::vector<uint8_t>;
  using CoseEndorsementsChain = std::vector<RawCoseEndorsement>;

  enum class FetchStatus : uint8_t
  {
    Retry,
    Done,
    Failed
  };

  class NetworkIdentitySubsystemInterface : public ccf::AbstractNodeSubSystem
  {
  public:
    ~NetworkIdentitySubsystemInterface() override = default;

    static char const* get_subsystem_name()
    {
      return "NetworkIdentity";
    }

    virtual const std::unique_ptr<NetworkIdentity>& get() = 0;

    [[nodiscard]] virtual FetchStatus endorsements_fetching_status() const = 0;

    [[nodiscard]] virtual std::optional<CoseEndorsementsChain>
    get_cose_endorsements_chain(ccf::SeqNo seqno) const = 0;

    [[nodiscard]] virtual ccf::crypto::ECPublicKeyPtr get_trusted_identity_for(
      ccf::SeqNo seqno) const = 0;
  };
}

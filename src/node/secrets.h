// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "rpc/jsonrpc.h"

#include <msgpack.hpp>
#include <vector>

namespace ccf
{
  // Because past network secrets are encrypted with an ephemeral key passed by
  // the followers to the leader as part of the join protocol, a given set of
  // past network secrets is encrypted with different keys for each follower
  struct SerialisedNetworkSecrets
  {
    NodeId node_id;
    std::vector<uint8_t> serial_ns;

    MSGPACK_DEFINE(node_id, serial_ns);
  };

  ADD_JSON_TRANSLATORS(SerialisedNetworkSecrets, node_id, serial_ns)

  struct PastNetworkSecrets
  {
    std::vector<SerialisedNetworkSecrets> secrets;

    MSGPACK_DEFINE(secrets);
  };

  ADD_JSON_TRANSLATORS(PastNetworkSecrets, secrets)

  // This map is used to communicate past network secrets from the leader to the
  // followers (e.g. during recovery)
  using Secrets = Store::Map<kv::Version, PastNetworkSecrets>;
}

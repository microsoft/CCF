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
  // the backups to the primary as part of the join protocol, a given set of
  // past network secrets is encrypted with different keys for each backup
  struct SerialisedNetworkSecrets
  {
    NodeId node_id;
    std::vector<uint8_t> serial_ns;

    MSGPACK_DEFINE(node_id, serial_ns);
  };

  DECLARE_JSON_TYPE(SerialisedNetworkSecrets)
  DECLARE_JSON_REQUIRED_FIELDS(SerialisedNetworkSecrets, node_id, serial_ns)

  struct PastNetworkSecrets
  {
    // TODO: Since ECDSA does not support asymmetric encryption out of the box,
    // pass the public key for now
    std::vector<uint8_t> primary_public_encryption_key;
    std::vector<SerialisedNetworkSecrets> secrets;

    MSGPACK_DEFINE(primary_public_encryption_key, secrets);
  };

  DECLARE_JSON_TYPE(PastNetworkSecrets)
  DECLARE_JSON_REQUIRED_FIELDS(
    PastNetworkSecrets, primary_public_encryption_key, secrets)

  // This map is used to communicate past network secrets from the primary to
  // the backups (e.g. during recovery)
  using Secrets = Store::Map<kv::Version, PastNetworkSecrets>;
}

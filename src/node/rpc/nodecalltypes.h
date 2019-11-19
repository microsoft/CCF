// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/json_schema.h"
#include "node/nodeinfonetwork.h"
#include "node/secret.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct GetSignedIndex
  {
    using In = void;

    enum class State
    {
      ReadingPublicLedger,
      ReadingPrivateLedger,
      PartOfNetwork,
      PartOfPublicNetwork,
    };

    struct Out
    {
      State state;
      kv::Version signed_index;
    };
  };

  struct GetQuotes
  {
    using In = void;

    struct Quote
    {
      NodeId node_id = {};
      std::vector<uint8_t> raw = {};

      std::string error = {};
      std::string mrenclave = {}; // < Hex-encoded
    };

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  struct CreateNetworkNodeToNode
  {
    struct In
    {
      std::vector<std::vector<uint8_t>> member_cert;
      std::string gov_script;
      std::vector<uint8_t> node_cert;
      Cert network_cert;
      std::vector<uint8_t> quote;
      std::vector<uint8_t> code_digest;
      NodeInfoNetwork node_info_network;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      std::vector<uint8_t> raw_fresh_key;
      NodeInfoNetwork node_info_network;
      std::vector<uint8_t> quote;
    };

    struct Out
    {
      NodeStatus node_status;
      NodeId node_id;

      struct NetworkInfo
      {
        Secret network_secrets;
        int64_t version; // Current version of the network secrets

        bool operator==(const NetworkInfo& other) const
        {
          return network_secrets == other.network_secrets &&
            version == other.version;
        }

        bool operator!=(const NetworkInfo& other) const
        {
          return !(*this == other);
        }
      };
      NetworkInfo network_info;
    };
  };
}
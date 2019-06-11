// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "entities.h"
#include "networksecrets.h"

namespace ccf
{
  struct StartNetwork
  {
    struct In
    {
      std::vector<uint8_t> tx0;
      NodeId id;
    };

    struct Out
    {
      std::string network_cert;
      // signed by network
      std::vector<uint8_t> tx0_sig;
    };
  };

  struct JoinNetwork
  {
    struct In
    {
      std::vector<uint8_t> network_cert;
      std::string hostname;
      std::string service;
    };

    struct Out
    {
      NodeId id;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      std::vector<uint8_t> raw_fresh_key;
    };

    struct Out
    {
      NodeId id;
      NetworkSecrets::Secret network_secrets;
      int64_t version; // Current version of the network secrets
    };
  };

  struct CreateNew
  {
    struct In
    {
      bool recover;
      size_t quote_max_size;
    };
    struct Out
    {
      std::vector<uint8_t> node_cert;
      std::vector<uint8_t> quote;
    };
  };
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "enclave/interface.h"
#include "enclave/nodeinfonetwork.h"
#include "entities.h"
#include "networksecrets.h"
#include "nodes.h"

namespace ccf
{
  struct CreateNew
  {
    struct In
    {
      CCFConfig config;
    };
    struct Out
    {
      std::vector<uint8_t> node_cert;
      std::vector<uint8_t> quote;
      std::vector<uint8_t> network_cert;
    };
  };

  struct CreateJoin
  {
    struct In
    {
      CCFConfig config;
    };

    struct Out
    {
      std::vector<uint8_t> node_cert;
      std::vector<uint8_t> quote;
    };
  };

  struct CreateRecover
  {
    struct In
    {
      NodeInfoNetwork node_info;
    };

    struct Out
    {
      std::vector<uint8_t> node_cert;
      std::vector<uint8_t> quote;
      std::vector<uint8_t> network_cert;
    };
  };

  // TODO: This will need to go
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

  // TODO: This will need to go
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

  struct GetSignedIndex
  {
    using In = void;

    enum class State
    {
      ReadingPublicLedger,
      AwaitingRecovery,
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

  struct SetRecoveryNodes
  {
    struct In
    {
      std::vector<NodeInfo> nodes;
    };

    using Out = void;
  };

  struct GetQuotes
  {
    using In = void;

    struct Quote
    {
      NodeId node_id = {};
      std::string raw = {};

      std::string error = {};
      std::string mrenclave = {};
    };

    struct Out
    {
      std::vector<Quote> quotes;
    };
  };

  struct JoinNetworkNodeToNode
  {
    struct In
    {
      std::vector<uint8_t> raw_fresh_key;
      NodeInfoNetwork node_info;
      std::vector<uint8_t> quote;
    };

    struct Out
    {
      NodeId id;
      NetworkSecrets::Secret network_secrets;
      int64_t version; // Current version of the network secrets
    };
  };
}

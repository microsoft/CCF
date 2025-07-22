// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/service/map.h"
#include "node/identity.h"

using IntrinsicIdentifier = std::string;

struct SelfHealOpenNodeInfo
{
  ccf::QuoteInfo quote_info;
  std::string published_network_address;
  std::vector<uint8_t> cert_der;
  IntrinsicIdentifier intrinsic_id;
};

DECLARE_JSON_TYPE(SelfHealOpenNodeInfo);
DECLARE_JSON_REQUIRED_FIELDS(
  SelfHealOpenNodeInfo, quote_info, published_network_address, cert_der);

namespace ccf
{
  using SelfHealOpenNodeState = ServiceMap<IntrinsicIdentifier,SelfHealOpenNodeInfo>;
  using SelfHealOpenGossipState = ServiceMap<IntrinsicIdentifier, ccf::kv::Version>;
  using SelfHealOpenChosenReplica = ServiceValue<IntrinsicIdentifier>;
  using SelfHealOpenVotes = ServiceSet<IntrinsicIdentifier>;

  namespace Tables
  {
    static constexpr auto SELF_HEAL_OPEN_NODES = "public:ccf.gov.selfhealopen.nodes";
    static constexpr auto SELF_HEAL_OPEN_GOSSIP_STATE = "public:ccf.gov.selfhealopen.gossip";
    static constexpr auto SELF_HEAL_OPEN_CHOSEN_REPLICA =
      "public:ccf.gov.selfhealopen.chosen_replica";
    static constexpr auto SELF_HEAL_OPEN_VOTES = "public:ccf.gov.selfhealopen.votes";
  }
}

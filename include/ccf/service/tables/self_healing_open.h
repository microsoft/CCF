// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/enum_formatter.h"
#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/service/map.h"
#include "ccf/service/node_info_network.h"


namespace ccf
{
  namespace self_healing_open
  {
    using IntrinsicIdentifier = std::string;
    using NetAddress = std::string;

    struct Identity
    {
      IntrinsicIdentifier intrinsic_id;
      NetAddress published_address;

      bool operator==(const Identity&) const = default;
    };

    DECLARE_JSON_TYPE(Identity);
    DECLARE_JSON_REQUIRED_FIELDS(
      Identity, intrinsic_id, published_address);

    struct NodeInfo
    {
      ccf::QuoteInfo quote_info;
      Identity identity;
      std::vector<uint8_t> cert_der;
      std::string service_identity;
    };

    DECLARE_JSON_TYPE(NodeInfo);
    DECLARE_JSON_REQUIRED_FIELDS(
      NodeInfo,
      quote_info,
      published_network_address,
      cert_der,
      service_identity,
      intrinsic_id);

    enum class StateMachine : uint8_t
    {
      GOSSIPING = 0,
      VOTING,
      OPENING, // by chosen node
      JOINING, // by all other replicas
      OPEN,
    };

    DECLARE_JSON_ENUM(
      StateMachine,
      {{StateMachine::GOSSIPING, "Gossiping"},
       {StateMachine::VOTING, "Voting"},
       {StateMachine::OPENING, "Opening"},
       {StateMachine::JOINING, "Joining"},
       {StateMachine::OPEN, "Open"}});

    using NodeInfoMap =
      ServiceMap<IntrinsicIdentifier, ccf::self_healing_open::NodeInfo>;
    using Gossips = ServiceMap<IntrinsicIdentifier, ccf::kv::Version>;
    using ChosenNode = ServiceValue<IntrinsicIdentifier>;
    using Votes = ServiceSet<IntrinsicIdentifier>;
    using SMState = ServiceValue<ccf::self_healing_open::StateMachine>;
    using TimeoutSMState = ServiceValue<ccf::self_healing_open::StateMachine>;
    using FailoverFlag = ServiceValue<bool>;
  }

  namespace Tables
  {
    static constexpr auto SELF_HEALING_OPEN_NODES =
      "public:ccf.gov.selfhealingopen.nodes";
    static constexpr auto SELF_HEALING_OPEN_GOSSIPS =
      "public:ccf.gov.selfhealingopen.gossip";
    static constexpr auto SELF_HEALING_OPEN_CHOSEN_NODE =
      "public:ccf.gov.selfhealingopen.chosen_node";
    static constexpr auto SELF_HEALING_OPEN_VOTES =
      "public:ccf.gov.selfhealingopen.votes";
    static constexpr auto SELF_HEALING_OPEN_SM_STATE =
      "public:ccf.gov.selfhealingopen.sm_state";
    static constexpr auto SELF_HEALING_OPEN_TIMEOUT_SM_STATE =
      "public:ccf.gov.selfhealingopen.timeout_sm_state";
    static constexpr auto SELF_HEALING_OPEN_FAILOVER_FLAG =
      "public:ccf.gov.selfhealingopen.failover_open";
  }
}

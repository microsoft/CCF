// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/enum_formatter.h"
#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/service/map.h"

using IntrinsicIdentifier = std::string;

struct SelfHealingOpenNodeInfo_t
{
  ccf::QuoteInfo quote_info;
  std::string published_network_address;
  std::vector<uint8_t> cert_der;
  std::string service_identity;
  IntrinsicIdentifier intrinsic_id;
};

DECLARE_JSON_TYPE(SelfHealingOpenNodeInfo_t);
DECLARE_JSON_REQUIRED_FIELDS(
  SelfHealingOpenNodeInfo_t,
  quote_info,
  published_network_address,
  cert_der,
  service_identity,
  intrinsic_id);

enum class SelfHealingOpenSM
{
  GOSSIPING = 0,
  VOTING,
  OPENING, // by chosen replica
  JOINING, // by all other replicas
  OPEN,
};

DECLARE_JSON_ENUM(
  SelfHealingOpenSM,
  {{SelfHealingOpenSM::GOSSIPING, "Gossiping"},
   {SelfHealingOpenSM::VOTING, "Voting"},
   {SelfHealingOpenSM::OPENING, "Opening"},
   {SelfHealingOpenSM::JOINING, "Joining"},
   {SelfHealingOpenSM::OPEN, "Open"}});

namespace ccf
{
  using SelfHealingOpenNodeInfo =
    ServiceMap<IntrinsicIdentifier, SelfHealingOpenNodeInfo_t>;
  using SelfHealingOpenGossips =
    ServiceMap<IntrinsicIdentifier, ccf::kv::Version>;
  using SelfHealingOpenChosenReplica = ServiceValue<IntrinsicIdentifier>;
  using SelfHealingOpenVotes = ServiceSet<IntrinsicIdentifier>;
  using SelfHealingOpenSMState = ServiceValue<SelfHealingOpenSM>;
  using SelfHealingOpenTimeoutSMState = ServiceValue<SelfHealingOpenSM>;
  using SelfHealingOpenFailoverFlag = ServiceValue<bool>;

  namespace Tables
  {
    static constexpr auto SELF_HEALING_OPEN_NODES =
      "public:ccf.gov.selfhealingopen.nodes";
    static constexpr auto SELF_HEALING_OPEN_GOSSIPS =
      "public:ccf.gov.selfhealingopen.gossip";
    static constexpr auto SELF_HEALING_OPEN_CHOSEN_REPLICA =
      "public:ccf.gov.selfhealingopen.chosen_replica";
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

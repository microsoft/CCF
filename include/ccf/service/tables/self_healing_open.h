// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/crypto/verifier.h"
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
    DECLARE_JSON_REQUIRED_FIELDS(Identity, intrinsic_id, published_address);

    inline std::string service_fingerprint_from_pem(const ccf::crypto::Pem& pem)
    {
      return ccf::crypto::Sha256Hash(
               ccf::crypto::public_key_der_from_cert(pem.raw()))
        .hex_str();
    }

    struct RequestNodeInfo
    {
      QuoteInfo quote_info;
      Identity identity;
      std::vector<uint8_t> service_cert_der;
    };
    DECLARE_JSON_TYPE(RequestNodeInfo);
    DECLARE_JSON_REQUIRED_FIELDS(
      RequestNodeInfo, quote_info, identity, service_cert_der);

    struct NodeInfo : RequestNodeInfo
    {
      std::vector<uint8_t> node_cert_der;
    };

    DECLARE_JSON_TYPE_WITH_BASE(NodeInfo, RequestNodeInfo);
    DECLARE_JSON_REQUIRED_FIELDS(NodeInfo, node_cert_der);

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

    enum class OpenKinds : uint8_t
    {
      QUORUM = 0,
      FAILOVER,
    };
    DECLARE_JSON_ENUM(
      OpenKinds,
      {{OpenKinds::QUORUM, "Quorum"}, {OpenKinds::FAILOVER, "Failover"}});

    using NodeInfoMap =
      ServiceMap<IntrinsicIdentifier, ccf::self_healing_open::NodeInfo>;
    using Gossips = ServiceMap<IntrinsicIdentifier, ccf::kv::Version>;
    using ChosenNode = ServiceValue<IntrinsicIdentifier>;
    using Votes = ServiceSet<IntrinsicIdentifier>;
    using SMState = ServiceValue<ccf::self_healing_open::StateMachine>;
    using TimeoutSMState = ServiceValue<ccf::self_healing_open::StateMachine>;
    using OpenKind = ServiceValue<ccf::self_healing_open::OpenKinds>;
  }

  namespace Tables
  {
    static constexpr auto SELF_HEALING_OPEN_NODES =
      "public:ccf.gov.self_healing_open.nodes";
    static constexpr auto SELF_HEALING_OPEN_GOSSIPS =
      "public:ccf.gov.self_healing_open.gossip";
    static constexpr auto SELF_HEALING_OPEN_CHOSEN_NODE =
      "public:ccf.gov.self_healing_open.chosen_node";
    static constexpr auto SELF_HEALING_OPEN_VOTES =
      "public:ccf.gov.self_healing_open.votes";
    static constexpr auto SELF_HEALING_OPEN_SM_STATE =
      "public:ccf.gov.self_healing_open.sm_state";
    static constexpr auto SELF_HEALING_OPEN_TIMEOUT_SM_STATE =
      "public:ccf.gov.self_healing_open.timeout_sm_state";
    static constexpr auto SELF_HEALING_OPEN_OPEN_KIND =
      "public:ccf.gov.self_healing_open.open_kind";
  }
}

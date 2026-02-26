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
#include "ccf/tx_id.h"

namespace ccf
{
  namespace sealing_recovery
  {
    using Name = std::string;
    using NetAddress = std::string;

    struct Location
    {
      Name name;
      NetAddress address;

      bool operator==(const Location&) const = default;
    };

    DECLARE_JSON_TYPE(Location);
    DECLARE_JSON_REQUIRED_FIELDS(Location, name, address);

  }
  namespace recovery_decision_protocol
  {
    inline std::string service_fingerprint_from_pem(const ccf::crypto::Pem& pem)
    {
      return ccf::crypto::Sha256Hash(
               ccf::crypto::public_key_der_from_cert(pem.raw()))
        .hex_str();
    }

    struct RequestNodeInfo
    {
      QuoteInfo quote_info;
      sealing_recovery::Location location;
      std::vector<uint8_t> service_cert_der;
    };
    DECLARE_JSON_TYPE(RequestNodeInfo);
    DECLARE_JSON_REQUIRED_FIELDS(
      RequestNodeInfo, quote_info, location, service_cert_der);

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

    using NodeInfoMap = ServiceMap<
      sealing_recovery::Name,
      ccf::recovery_decision_protocol::NodeInfo>;
    using Gossips = ServiceMap<sealing_recovery::Name, ccf::TxID>;
    using ChosenNode = ServiceValue<sealing_recovery::Name>;
    using Votes = ServiceSet<sealing_recovery::Name>;
    using SMState = ServiceValue<ccf::recovery_decision_protocol::StateMachine>;
    using TimeoutSMState =
      ServiceValue<ccf::recovery_decision_protocol::StateMachine>;
    using OpenKind = ServiceValue<ccf::recovery_decision_protocol::OpenKinds>;
  }

  namespace Tables
  {
    static constexpr auto RECOVERY_DECISION_PROTOCOL_NODES =
      "public:ccf.gov.recovery_decision_protocol.nodes";
    static constexpr auto RECOVERY_DECISION_PROTOCOL_GOSSIPS =
      "public:ccf.gov.recovery_decision_protocol.gossip";
    static constexpr auto RECOVERY_DECISION_PROTOCOL_CHOSEN_NODE =
      "public:ccf.gov.recovery_decision_protocol.chosen_node";
    static constexpr auto RECOVERY_DECISION_PROTOCOL_VOTES =
      "public:ccf.gov.recovery_decision_protocol.votes";
    static constexpr auto RECOVERY_DECISION_PROTOCOL_SM_STATE =
      "public:ccf.gov.recovery_decision_protocol.sm_state";
    static constexpr auto RECOVERY_DECISION_PROTOCOL_TIMEOUT_SM_STATE =
      "public:ccf.gov.recovery_decision_protocol.timeout_sm_state";
    static constexpr auto RECOVERY_DECISION_PROTOCOL_OPEN_KIND =
      "public:ccf.gov.recovery_decision_protocol.open_kind";
  }
}

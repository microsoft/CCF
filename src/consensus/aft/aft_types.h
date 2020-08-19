// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/consensus_types.h"
#include "consensus/pbft/pbft_requests.h"
#include "enclave/rpc_context.h"
#include "enclave/rpc_handler.h"
#include "kv/kv_types.h"
#include "kv/store.h"

#include <functional>
#include <vector>

namespace ccf
{
  class NodeToNode;
}

namespace enclave
{
  class RPCMap;
}

namespace aft
{
  enum AftMsgType : ccf::Node2NodeMsg
  {
    aft_message = 1000,
    encrypted_aft_message,
    aft_append_entries
  };

#pragma pack(push, 1)
  struct AftHeader
  {
    AftMsgType msg;
    kv::NodeId from_node;
  };

  struct AppendEntries : consensus::ConsensusHeader<AftMsgType>,
                         consensus::AppendEntriesIndex
  {};

#pragma pack(pop)
  class RequestMessage;
  class EnclaveNetwork;
  struct RequestCtx
  {
    std::shared_ptr<enclave::RpcContext> ctx;
    std::shared_ptr<enclave::RpcHandler> frontend;
  };

  using ReplyCallback = std::function<bool(
    void* owner,
    kv::TxHistory::RequestID caller_rid,
    int status,
    std::vector<uint8_t>& data)>;

  class IStore
  {
  public:
    virtual ~IStore() = default;
    virtual kv::DeserialiseSuccess deserialise_views(
      const std::vector<uint8_t>& data,
      bool public_only = false,
      kv::Term* term = nullptr,
      kv::Tx* tx = nullptr) = 0;
    virtual void compact(kv::Version v) = 0;
    virtual kv::Version current_version() = 0;
  };

  class IStateMachine
  {
  public:
    IStateMachine() = default;
    virtual ~IStateMachine() = default;

    virtual void receive_request(std::unique_ptr<RequestMessage> request) = 0;
    virtual void receive_message(OArray oa, kv::NodeId from) = 0;
    virtual void receive_message(
      OArray oa, AppendEntries ae, kv::NodeId from) = 0;
    virtual void add_node(
      kv::NodeId node_id, const std::vector<uint8_t>& cert) = 0;
    virtual bool is_primary() = 0;
    virtual kv::NodeId primary() = 0;
    virtual kv::Consensus::View view() = 0;
    virtual kv::Consensus::View get_view_for_version(kv::Version version) = 0;
    virtual kv::Version get_last_committed_version() = 0;
    virtual void attempt_to_open_network() = 0;
  };

  std::unique_ptr<IStateMachine> create_state_machine(
    kv::NodeId my_node_id,
    const std::vector<uint8_t>& cert,
    IStore& store,
    std::shared_ptr<EnclaveNetwork> network,
    std::shared_ptr<enclave::RPCMap> rpc_map,
    pbft::RequestsMap& pbft_requests_map);

  std::unique_ptr<IStore> create_store_adaptor(
    std::shared_ptr<kv::Store> store);
}
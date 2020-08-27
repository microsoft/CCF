// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "aft_state.h"
#include "consensus/aft/raft_types.h"
#include "consensus/pbft/pbft_requests.h"
#include "enclave/rpc_map.h"

namespace enclave
{
  class RPCSessions;
  class RPCMap;
}

namespace aft
{
  class RequestMessage;

  class ExecutionUtilities
  {
  public:
    virtual ~ExecutionUtilities() = default;

    virtual std::unique_ptr<RequestCtx> create_request_ctx(
      uint8_t* req_start, size_t req_size) = 0;

    virtual std::unique_ptr<RequestCtx> create_request_ctx(
      pbft::Request& request) = 0;

    virtual kv::Version execute_request(
      std::unique_ptr<RequestMessage> request, bool is_create_request) = 0;

    virtual std::unique_ptr<aft::RequestMessage> create_request_message(
      const kv::TxHistory::RequestCallbackArgs& args) = 0;

    virtual kv::Version commit_replayed_request(kv::Tx& tx) = 0;
  };

  class ExecutionUtilitiesImpl : public ExecutionUtilities
  {
  public:
    ExecutionUtilitiesImpl(
      pbft::RequestsMap& pbft_requests_map_,
      std::shared_ptr<ServiceState> state_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      std::shared_ptr<enclave::RPCSessions> rpc_sessions_) :
      pbft_requests_map(pbft_requests_map_),
      state(state_),
      rpc_map(rpc_map_),
      rpc_sessions(rpc_sessions_)
    {}

    std::unique_ptr<RequestCtx> create_request_ctx(
      uint8_t* req_start, size_t req_size) override;

    std::unique_ptr<RequestCtx> create_request_ctx(
      pbft::Request& request) override;

    kv::Version execute_request(
      std::unique_ptr<RequestMessage> request, bool is_create_request) override;

    std::unique_ptr<aft::RequestMessage> create_request_message(
      const kv::TxHistory::RequestCallbackArgs& args) override;

    kv::Version commit_replayed_request(kv::Tx& tx) override;

  private:
    pbft::RequestsMap& pbft_requests_map;
    std::shared_ptr<ServiceState> state;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<enclave::RPCSessions> rpc_sessions;
  };
}

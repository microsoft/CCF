// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/buffer.h"
#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

#include <vector>

namespace enclave
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();

  struct RPCContext
  {
    //
    // In parameters (initialised when context is created)
    //

    // Session ID with client
    const size_t session_id = InvalidSessionId;
    // Actor type to route to appropriate frontend
    const ccf::ActorsType actor;
    // Caller certificate
    CBuffer caller;

    //
    // Out parameters (changed during lifetime of context)
    //

    // If true, the RPC does not reply to the client synchronously
    bool is_suspended = false;
    // Packing method used to serialise the RPC object
    std::optional<jsonrpc::Pack> pack = std::nullopt;
    // JSON-RPC specific
    struct json
    {
      uint64_t seq_no;
    };
    struct json json;

    //
    // Only true if the command has been forwarded
    //
    struct forwarded
    {
      const size_t session_id;
      const ccf::NodeId from;
      const ccf::CallerId caller_id;

      ccf::NodeId leader_id;

      forwarded(
        size_t session_id_, ccf::NodeId from_, ccf::CallerId caller_id_) :
        session_id(session_id_),
        from(from_),
        caller_id(caller_id_)
      {}

      forwarded() = default;
    };
    std::optional<struct forwarded> fwd = std::nullopt;

    // Constructor used for non-forwarded RPC
    RPCContext(
      size_t session_id_,
      CBuffer caller_,
      ccf::ActorsType actor_ = ccf::ActorsType::unknown) :
      session_id(session_id_),
      caller(caller_),
      actor(actor_)
    {}

    // Constructor used for forwarded RPC
    RPCContext(
      size_t fwd_session_id_,
      ccf::NodeId from_,
      ccf::CallerId caller_id_,
      ccf::ActorsType actor_ = ccf::ActorsType::unknown) :
      fwd(std::make_optional<struct forwarded>(
        fwd_session_id_, from_, caller_id_)),
      actor(actor_)
    {}
  };

  class AbstractRPCResponder
  {
  public:
    virtual ~AbstractRPCResponder() {}
    virtual void reply_async(size_t id, const std::vector<uint8_t>& data) = 0;
  };
}
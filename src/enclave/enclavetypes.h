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

    const size_t client_session_id = InvalidSessionId;
    CBuffer caller_cert;
    // Actor type to route to appropriate frontend
    const ccf::ActorsType actor;

    //
    // Out parameters (changed during lifetime of context)
    //

    // If true, the RPC does not reply to the client synchronously
    bool is_pending = false;
    std::optional<jsonrpc::Pack> pack = std::nullopt;
    // Request payload specific attributes
    struct request
    {
      uint64_t seq_no;
    };
    struct request req;

    //
    // Only set in the case of a forwarded RPC
    //
    struct forwarded
    {
      // Initialised when forwarded context is created
      const size_t client_session_id;
      const ccf::NodeId from;
      const ccf::CallerId caller_id;

      // Changed during lifetime of forwarded context
      ccf::NodeId primary_id = ccf::INVALID_ID;

      forwarded(
        size_t client_session_id_,
        ccf::NodeId from_,
        ccf::CallerId caller_id_) :
        client_session_id(client_session_id_),
        from(from_),
        caller_id(caller_id_)
      {}
    };
    std::optional<struct forwarded> fwd = std::nullopt;

    // Constructor used for non-forwarded RPC
    RPCContext(
      size_t client_session_id_,
      CBuffer caller_cert_,
      ccf::ActorsType actor_ = ccf::ActorsType::unknown) :
      client_session_id(client_session_id_),
      caller_cert(caller_cert_),
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
    virtual bool reply_async(size_t id, const std::vector<uint8_t>& data) = 0;
  };
}
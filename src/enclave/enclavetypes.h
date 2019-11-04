// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/entities.h"
#include "node/rpc/jsonrpc.h"

#include <vector>

namespace enclave
{
  static constexpr size_t InvalidSessionId = std::numeric_limits<size_t>::max();

  struct SessionContext
  {
    size_t client_session_id = InvalidSessionId;
    std::vector<uint8_t> caller_cert = {};

    //
    // Only set in the case of a forwarded RPC
    //
    struct Forwarded
    {
      // Initialised when forwarded context is created
      const size_t client_session_id;
      const ccf::CallerId caller_id;

      Forwarded(size_t client_session_id_, ccf::CallerId caller_id_) :
        client_session_id(client_session_id_),
        caller_id(caller_id_)
      {}
    };
    std::optional<Forwarded> fwd = std::nullopt;

    // Constructor used for non-forwarded RPC
    SessionContext(
      size_t client_session_id_, const std::vector<uint8_t>& caller_cert_) :
      client_session_id(client_session_id_),
      caller_cert(caller_cert_)
    {}

    // Constructor used for forwarded and PBFT RPC
    SessionContext(
      size_t fwd_session_id_,
      ccf::CallerId caller_id_,
      const std::vector<uint8_t>& caller_cert_ = {}) :
      fwd(std::make_optional<Forwarded>(fwd_session_id_, caller_id_)),
      caller_cert(caller_cert_)
    {}
  };

  struct RPCContext
  {
    SessionContext session;

    // Packing format of original request, should be used to pack response
    std::optional<jsonrpc::Pack> pack = std::nullopt;

    // TODO: Avoid unnecessary copies
    std::vector<uint8_t> raw = {};

    nlohmann::json unpacked_rpc = {};

    std::optional<ccf::SignedReq> signed_request = std::nullopt;

    // Actor type to dispatch to appropriate frontend
    ccf::ActorsType actor = ccf::ActorsType::unknown;

    // Method indicates specific handler for this request
    std::string method = {};

    uint64_t seq_no = {};

    nlohmann::json params = {};

    bool is_create_request = false;

    RPCContext(const SessionContext& s) : session(s) {}
  };

  inline void parse_rpc_context(RPCContext& rpc_ctx, const nlohmann::json& rpc)
  {
    const auto sig_it = rpc.find(jsonrpc::SIG);
    if (sig_it != rpc.end())
    {
      rpc_ctx.unpacked_rpc = rpc.at(jsonrpc::REQ);
      ccf::SignedReq signed_req;
      signed_req.sig = sig_it->get<decltype(signed_req.sig)>();
      signed_req.req = nlohmann::json::to_msgpack(rpc_ctx.unpacked_rpc);
      rpc_ctx.signed_request = signed_req;
    }
    else
    {
      rpc_ctx.unpacked_rpc = rpc;
      rpc_ctx.signed_request = std::nullopt;
    }

    const auto method_it = rpc_ctx.unpacked_rpc.find(jsonrpc::METHOD);
    if (method_it != rpc_ctx.unpacked_rpc.end())
    {
      rpc_ctx.method = method_it->get<std::string>();
    }

    const auto seq_it = rpc_ctx.unpacked_rpc.find(jsonrpc::ID);
    if (seq_it != rpc_ctx.unpacked_rpc.end())
    {
      rpc_ctx.seq_no = seq_it->get<uint64_t>();
    }

    const auto params_it = rpc_ctx.unpacked_rpc.find(jsonrpc::PARAMS);
    if (params_it != rpc_ctx.unpacked_rpc.end())
    {
      rpc_ctx.params = *params_it;
    }
  }

  inline RPCContext make_rpc_context(
    const SessionContext& s, const std::vector<uint8_t>& packed)
  {
    RPCContext rpc_ctx(s);

    auto [success, rpc] = jsonrpc::unpack_rpc(packed, rpc_ctx.pack);
    if (!success)
    {
      throw std::logic_error(fmt::format("Failed to unpack: {}", rpc.dump()));
    }

    parse_rpc_context(rpc_ctx, rpc);
    rpc_ctx.raw = packed;

    return rpc_ctx;
  }

  class AbstractRPCResponder
  {
  public:
    virtual ~AbstractRPCResponder() {}
    virtual bool reply_async(size_t id, const std::vector<uint8_t>& data) = 0;
  };

  class AbstractForwarder
  {
  public:
    virtual ~AbstractForwarder() {}

    virtual bool forward_command(
      const enclave::RPCContext& rpc_ctx,
      ccf::NodeId to,
      ccf::CallerId caller_id,
      const std::vector<uint8_t>& caller_cert) = 0;
  };
}
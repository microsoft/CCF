// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http.h"
#include "node/rpc/jsonrpc.h"
#include "rpcmap.h"
#include "tlsframedendpoint.h"

namespace enclave
{
#ifdef HTTP
  using ServerEndpoint = HTTPEndpoint<http::ResponseHeaderEmitter>;
#else
  using ServerEndpoint = FramedTLSEndpoint;
#endif

  class RPCEndpoint : public ServerEndpoint
  {
  private:
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RpcHandler> handler;
    ccf::ActorsType actor;
    size_t session_id;
    CBuffer caller;

  public:
    RPCEndpoint(
      std::shared_ptr<RPCMap> rpc_map_,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      ServerEndpoint(session_id, writer_factory, move(ctx)),
      rpc_map(rpc_map_),
      session_id(session_id)
    {}

    auto split_actor_and_method(const std::string& actor_method)
    {
      const auto split_point = actor_method.find_last_of('/');
      const auto actor = actor_method.substr(0, split_point);
      const auto method =
        actor_method.substr(split_point + 1, actor_method.size());

      // NB: If the string does not contain '/', then both actor and method will
      // contain the entire string
      return std::make_pair(actor, method);
    }

    bool handle_data(const std::vector<uint8_t>& data) override
    {
      LOG_DEBUG_FMT(
        "Entered handle_data, session {} with {} bytes",
        session_id,
        data.size());

      const SessionContext session(session_id, peer_cert());
      RPCContext rpc_ctx(session);

      auto [success, rpc] = jsonrpc::unpack_rpc(data, rpc_ctx.pack);
      if (!success)
      {
        send(jsonrpc::pack(rpc, rpc_ctx.pack.value()));
        return true;
      }
      LOG_TRACE_FMT("Deserialised");

      parse_rpc_context(rpc_ctx, rpc);
      rpc_ctx.raw = data;

      auto prefixed_method = rpc_ctx.method;
      if (prefixed_method.empty())
      {
        send(jsonrpc::pack(
          jsonrpc::error_response(
            rpc_ctx.seq_no,
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            "No method specified"),
          rpc_ctx.pack.value()));
        return true;
      }

      // Separate JSON-RPC method into actor and true method
      auto [actor_s, method] = split_actor_and_method(prefixed_method);
      rpc_ctx.method = method;

      LOG_TRACE_FMT(
        "Parsed actor {}, method {} (from {})",
        actor_s,
        method,
        prefixed_method);

      auto actor = rpc_map->resolve(actor_s);
      if (actor == ccf::ActorsType::unknown)
      {
        send(jsonrpc::pack(
          jsonrpc::error_response(
            rpc_ctx.seq_no,
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            fmt::format("No such prefix: {}", actor_s)),
          rpc_ctx.pack.value()));
        return true;
      }
      rpc_ctx.actor = actor;

      auto search = rpc_map->find(actor);
      if (!search.has_value())
      {
        LOG_TRACE_FMT("No frontend found for actor {}", actor);
        return false;
      }

      // Hand off parsed context to be processed by frontend
      LOG_TRACE_FMT("Processing");
      auto response = search.value()->process(rpc_ctx);

      if (!response.has_value())
      {
        // If the RPC is pending, hold the connection.
        LOG_TRACE_FMT("Pending");
        return true;
      }
      else
      {
        // Otherwise, reply to the client synchronously.
        LOG_TRACE_FMT("Responding");
        send(response.value());
      }

      return true;
    }

    std::vector<uint8_t> oversized_message_error(
      size_t msg_size, size_t max_msg_size) override
    {
      return jsonrpc::pack(
        jsonrpc::error_response(
          0,
          jsonrpc::StandardErrorCodes::PARSE_ERROR,
          fmt::format(
            "Requested message ({} bytes) is too large. Maximum allowed is {} "
            "bytes. Closing connection.",
            msg_size,
            max_msg_size)),
        jsonrpc::Pack::Text);
    }
  };
}

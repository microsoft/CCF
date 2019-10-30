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

    std::optional<std::string> get_method(const nlohmann::json& j)
    {
      if (j.find(jsonrpc::SIG) != j.end())
      {
        return j.at(jsonrpc::REQ).at(jsonrpc::METHOD).get<std::string>();
      }
      else
      {
        return j.at(jsonrpc::METHOD).get<std::string>();
      }
    }

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

    bool handle_data(const std::vector<uint8_t>& data)
    {
      LOG_TRACE_FMT("Entered handle_data {} {}", data.size(), data.empty());

      // TODO: This does much of the same work as make_rpc_context. Work out if
      // they can be combined, with different error reporting in this version

      RPCContext rpc_ctx(session_id, peer_cert());
      auto [success, rpc] = jsonrpc::unpack_rpc(data, rpc_ctx.pack);

      if (!success)
      {
        send(jsonrpc::pack(rpc, rpc_ctx.pack.value_or(jsonrpc::Pack::Text)));
        return true;
      }
      LOG_TRACE_FMT("Deserialised");

      rpc_ctx.seq_no = rpc.value(jsonrpc::ID, 0);

      auto prefixed_method = get_method(rpc);
      if (!prefixed_method.has_value())
      {
        send(jsonrpc::pack(
          jsonrpc::error_response(
            rpc_ctx.seq_no,
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            "No method specified"),
          rpc_ctx.value()));
        return true;
      }
      LOG_TRACE_FMT("Got method");

      auto [actor_s, method] = split_actor_and_method(prefixed_method.value());
      rpc_ctx.method = method;

      auto actor = rpc_map->resolve(actor_s);
      if (actor == ccf::ActorsType::unknown)
      {
        send(jsonrpc::pack(
          jsonrpc::error_response(
            rpc_ctx.seq_no,
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            fmt::format("No such prefix: {}", actor_s)),
          rpc_ctx.value()));
        return true;
      }
      rpc_ctx.actor = actor;

      auto search = rpc_map->find(actor);
      if (!search.has_value())
        return false;

      auto response = search.value()->process(rpc_ctx, rpc, data);

      if (!response.has_value())
      {
        // If the RPC is pending, hold the connection.
        return true;
      }
      else
      {
        // Otherwise, reply to the client synchronously.
        send(response);
      }

      return true;
    }
  };
}

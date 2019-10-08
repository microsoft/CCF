// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../node/rpc/jsonrpc.h"
#include "http.h"
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
    std::shared_ptr<RpcMap> rpc_map;
    std::shared_ptr<RpcHandler> handler;
    ccf::ActorsType actor;
    size_t session_id;
    CBuffer caller;

  public:
    RPCEndpoint(
      std::shared_ptr<RpcMap> rpc_map_,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      ServerEndpoint(session_id, writer_factory, move(ctx)),
      rpc_map(rpc_map_),
      session_id(session_id)
    {}

    std::optional<jsonrpc::Pack> detect_pack(const std::vector<uint8_t>& input)
    {
      if (input.empty())
        return std::nullopt;

      if (input[0] == '{')
        return jsonrpc::Pack::Text;
      else
        return jsonrpc::Pack::MsgPack;
    }

    std::pair<bool, nlohmann::json> unpack_json(
      const std::vector<uint8_t>& input, jsonrpc::Pack pack)
    {
      nlohmann::json rpc;
      try
      {
        rpc = jsonrpc::unpack(input, pack);
        if (!rpc.is_object())
          return jsonrpc::error(
            jsonrpc::StandardErrorCodes::INVALID_REQUEST,
            fmt::format("RPC payload is a not a valid object: {}", rpc.dump()));
      }
      catch (const std::exception& e)
      {
        return jsonrpc::error(
          jsonrpc::StandardErrorCodes::INVALID_REQUEST,
          fmt::format("Exception during unpack: {}", e.what()));
      }

      return {true, rpc};
    }

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

    std::string get_actor(const std::string& method)
    {
      return method.substr(0, method.find_last_of('/'));
    }

    bool handle_data(const std::vector<uint8_t>& data)
    {
      LOG_TRACE_FMT("Entered handle_data {} {}", data.size(), data.empty());
      auto pack = detect_pack(data);
      if (!pack.has_value())
      {
        LOG_TRACE_FMT("NO PACK");
        send(jsonrpc::pack(
          jsonrpc::error_response(
            0, jsonrpc::StandardErrorCodes::INVALID_REQUEST, "Empty request."),
          jsonrpc::Pack::Text));
        return true;
      }

      LOG_TRACE_FMT("Detected");
      auto [deserialised, rpc] = unpack_json(data, pack.value());

      if (!deserialised)
      {
        send(jsonrpc::pack(rpc, pack.value()));
        return true;
      }
      LOG_TRACE_FMT("Deserialised");

      auto method = get_method(rpc);
      if (!method.has_value())
      {
        send(jsonrpc::pack(
          jsonrpc::error_response(
            rpc.value(jsonrpc::ID, 0),
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            "No method specified"),
          pack.value()));
        return true;
      }
      LOG_TRACE_FMT("Got method");

      std::string actor_prefix = get_actor(method.value());

      auto actor = rpc_map->resolve(actor_prefix);
      if (actor == ccf::ActorsType::unknown)
      {
        send(jsonrpc::pack(
          jsonrpc::error_response(
            rpc.value(jsonrpc::ID, 0),
            jsonrpc::StandardErrorCodes::METHOD_NOT_FOUND,
            fmt::format("No such prefix: {}", actor_prefix)),
          pack.value()));
        return true;
      }

      auto search = rpc_map->find(actor);
      if (!search.has_value())
        return false;

      RPCContext rpc_ctx(session_id, peer_cert(), actor);
      auto rep = search.value()->process(rpc_ctx, data);

      if (rpc_ctx.is_pending)
      {
        // If the RPC has been forwarded, hold the connection.
        return true;
      }
      else
      {
        // Otherwise, reply to the client synchronously.
        send(rep);
      }

      return true;
    }
  };
}

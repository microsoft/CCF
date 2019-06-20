// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "rpcmap.h"
#include "tlsframedendpoint.h"

namespace enclave
{
  class RPCEndpoint : public FramedTLSEndpoint
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
      FramedTLSEndpoint(session_id, writer_factory, move(ctx)),
      rpc_map(rpc_map_),
      session_id(session_id)
    {}

    bool handle_data(const std::vector<uint8_t>& data)
    {
      if (!handler)
      {
        // The hostname indicates the rpc class.
        auto host = hostname();

        actor = rpc_map->resolve(host);
        if (actor == ccf::ActorsType::unknown)
          return false;

        auto search = rpc_map->find(actor);
        if (!search.has_value())
          return false;

        // If there is a client cert, pass it to the rpc handler.
        LOG_DEBUG_FMT("RPC endpoint {}: {}", session_id, host);
        handler = search.value();
        caller = peer_cert();
      }

      // Create a new RPC context for each command since some may require
      // forwarding to the leader.
      RPCContext rpc_ctx(session_id, caller, actor);
      auto rep = handler->process(rpc_ctx, data);

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

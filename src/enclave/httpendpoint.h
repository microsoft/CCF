// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "httpparser.h"
#include "rpcmap.h"

namespace enclave
{
  template <class E>
  class HTTPEndpoint : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RpcHandler> handler;
    size_t session_id;

  public:
    HTTPEndpoint(
      std::shared_ptr<RPCMap> rpc_map,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) = delete;

    void recv(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      LOG_TRACE_FMT("recv called with {} bytes", size);

      auto buf = read_all_available();

      if (buf.size() == 0)
      {
        return;
      }

      LOG_TRACE_FMT(
        "Going to parse {} bytes: [{}]",
        buf.size(),
        std::string(buf.begin(), buf.end()));

      // TODO: This should return an error to the client if this fails
      if (p.execute(buf.data(), buf.size()) == 0)
      {
        LOG_FAIL_FMT("Failed to parse request");
        return;
      }
    }

    virtual void msg(
      http_method method,
      const std::string& path,
      const std::string& query,
      std::vector<uint8_t> body)
    {
      try
      {
        const SessionContext session(session_id, peer_cert());
        RPCContext rpc_ctx(session);

        const auto body_json = nlohmann::json::parse(body);
        parse_rpc_context(rpc_ctx, body_json);
        rpc_ctx.raw = body;

        const auto first_slash = path.find_first_of('/');
        const auto second_slash = path.find_first_of('/', first_slash + 1);

        if (
          first_slash != 0 || first_slash == std::string::npos ||
          second_slash == std::string::npos)
        {
          // TODO: Send error
          return;
        }

        const auto actor_s = path.substr(first_slash + 1, second_slash - 1);
        const auto method_s = path.substr(second_slash + 1);

        if (actor_s.empty() || actor_s.empty())
        {
          // TODO: Send error
          return;
        }

        auto actor = rpc_map->resolve(actor_s);
        if (actor == ccf::ActorsType::unknown)
        {
          // TODO: Send error
          return;
        }

        rpc_ctx.actor = actor;

        // TODO: This is temporary; while we have a full RPC object including
        // method inside the body, it should match the method specified in the
        // URI
        if (rpc_ctx.method != method_s)
        {
          // TODO: Send error
          return;
        }
        rpc_ctx.method = method_s;

        auto search = rpc_map->find(actor);
        if (!search.has_value())
        {
          // TODO: Send error
          return;
        }

        if (!search.value()->is_open())
        {
          // TODO: Send error
          return;
        }

        auto response = search.value()->process(rpc_ctx);

        if (!response.has_value())
        {
          // If the RPC is pending, hold the connection.
          LOG_TRACE_FMT("Pending");
          return;
        }
        else
        {
          // Otherwise, reply to the client synchronously.
          LOG_TRACE_FMT("Responding");
          send(response.value());
        }
      }
      catch (...)
      {
        // TODO: Should try to return an error first?
        // On any exception, close the connection.
        close();
      }
    }

    void send(const std::vector<uint8_t>& data)
    {
      send_buffered(E::emit(data));
      if (data.size() > 0)
      {
        send_buffered(data);
      }
      flush();
    }
  };

  template <>
  HTTPEndpoint<http::RequestHeaderEmitter>::HTTPEndpoint(
    std::shared_ptr<RPCMap> rpc_map,
    size_t session_id,
    ringbuffer::AbstractWriterFactory& writer_factory,
    std::unique_ptr<tls::Context> ctx) :
    TLSEndpoint(session_id, writer_factory, std::move(ctx)),
    p(HTTP_RESPONSE, *this),
    rpc_map(rpc_map),
    session_id(session_id)
  {}

  template <>
  HTTPEndpoint<http::ResponseHeaderEmitter>::HTTPEndpoint(
    std::shared_ptr<RPCMap> rpc_map,
    size_t session_id,
    ringbuffer::AbstractWriterFactory& writer_factory,
    std::unique_ptr<tls::Context> ctx) :
    TLSEndpoint(session_id, writer_factory, std::move(ctx)),
    p(HTTP_REQUEST, *this),
    rpc_map(rpc_map),
    session_id(session_id)
  {}
}
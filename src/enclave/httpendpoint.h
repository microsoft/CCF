// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "httpparser.h"
#include "rpcmap.h"

namespace enclave
{
  template <class E>
  class HTTPEndpoint : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;

  public:
    HTTPEndpoint(
      http_parser_type parser_type,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(parser_type, *this)
    {}

    void recv(const uint8_t* data, size_t size) override
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

    void send(const std::string& s)
    {
      send(std::vector<uint8_t>(s.begin(), s.end()));
    }

    void send(const std::vector<uint8_t>& data) override
    {
      LOG_INFO_FMT(
        "Sending response of {} bytes: {}",
        data.size(),
        nlohmann::json::parse(data).dump(2));
      send_buffered(E::emit(data));
      if (data.size() > 0)
      {
        send_buffered(data);
      }
      flush();
    }
  };

  class HTTPServerEndpoint : public HTTPEndpoint<http::ResponseHeaderEmitter>
  {
  private:
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RpcHandler> handler;
    size_t session_id;

  public:
    HTTPServerEndpoint(
      std::shared_ptr<RPCMap> rpc_map,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint<http::ResponseHeaderEmitter>(
        HTTP_REQUEST, session_id, writer_factory, std::move(ctx)),
      rpc_map(rpc_map),
      session_id(session_id)
    {}

    void msg(
      http_method method,
      const std::string& path,
      const std::string& query,
      std::vector<uint8_t> body) override
    {
      LOG_INFO_FMT(
        "Processing msg({}, {}, {}, [{} bytes])",
        http_method_str(method),
        path,
        query,
        body.size());

      try
      {
        const SessionContext session(session_id, peer_cert());
        RPCContext rpc_ctx(session);

        auto [success, json_rpc] = jsonrpc::unpack_rpc(body, rpc_ctx.pack);
        if (!success)
        {
          LOG_FAIL_FMT("Failed to unpack body", path);
          return;
        }

        parse_rpc_context(rpc_ctx, json_rpc);
        rpc_ctx.raw = body;

        const auto first_slash = path.find_first_of('/');
        const auto second_slash = path.find_first_of('/', first_slash + 1);

        if (
          first_slash != 0 || first_slash == std::string::npos ||
          second_slash == std::string::npos)
        {
          LOG_FAIL_FMT("Not happy with the slashes in {}", path);
          return;
        }

        const auto actor_s = path.substr(first_slash + 1, second_slash - 1);
        const auto method_s = path.substr(second_slash + 1);

        if (actor_s.empty() || method_s.empty())
        {
          // TODO: Send error
          LOG_FAIL_FMT("EMPTY: '{}' || '{}'", actor_s, method_s);
        }

        auto actor = rpc_map->resolve(actor_s);
        if (actor == ccf::ActorsType::unknown)
        {
          // TODO: Send error
          LOG_FAIL_FMT("{} == unknown", actor);
        }

        rpc_ctx.actor = actor;

        // TODO: This is temporary; while we have a full RPC object inside the
        // body, it should match the dispatch details specified in the URI
        if (rpc_ctx.method != fmt::format("{}/{}", actor_s, method_s))
        {
          // TODO: Send error
          LOG_FAIL_FMT("{} != {}", rpc_ctx.method, method_s);
        }
        rpc_ctx.method = method_s;

        auto search = rpc_map->find(actor);
        if (!search.has_value())
        {
          LOG_FAIL_FMT("Couldn't find actor {}", actor);
          return;
        }

        if (!search.value()->is_open())
        {
          LOG_FAIL_FMT("Session is not open {}", actor);
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
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception while processing HTTP message: {}", e.what());
        // TODO: Should try to return an error first?
        // On any exception, close the connection.
        close();
      }
    }
  };

  class HTTPClientEndpoint : public HTTPEndpoint<http::RequestHeaderEmitter>
  {
    using HandleDataCallback =
      std::function<bool(const std::vector<uint8_t>& data)>;

  private:
    HandleDataCallback handle_data_cb;

  public:
    HTTPClientEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint<http::RequestHeaderEmitter>(
        HTTP_RESPONSE, session_id, writer_factory, std::move(ctx))
    {}

    void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f)
    {
      RINGBUFFER_WRITE_MESSAGE(
        tls::tls_connect, to_host, session_id, hostname, service);
      handle_data_cb = f;
    }

    void msg(
      http_method method,
      const std::string& path,
      const std::string& query,
      std::vector<uint8_t> body) override
    {
      handle_data_cb(body);

      close();
    }
  };
}
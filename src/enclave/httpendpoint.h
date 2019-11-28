// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "clientendpoint.h"
#include "ds/logger.h"
#include "httpparser.h"
#include "rpcmap.h"

namespace enclave
{
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

      while (true)
      {
        auto buf = read(4096, false);
        if (buf.size() == 0)
        {
          return;
        }

        LOG_TRACE_FMT(
          "Going to parse {} bytes: \n[{}]",
          buf.size(),
          std::string(buf.begin(), buf.end()));

        // TODO: This should return an error to the client if this fails
        if (p.execute(buf.data(), buf.size()) == 0)
        {
          LOG_FAIL_FMT("Failed to parse request");
          return;
        }
      }
    }
  };

  class HTTPServerEndpoint : public HTTPEndpoint
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
      HTTPEndpoint(HTTP_REQUEST, session_id, writer_factory, std::move(ctx)),
      rpc_map(rpc_map),
      session_id(session_id)
    {}

    void send(const std::vector<uint8_t>& data) override
    {
      // This should be called with raw body of response - we will wrap it with
      // header then transmit
      send_response(data);
    }

    void send_response(const std::string& data)
    {
      send_response(std::vector<uint8_t>(data.begin(), data.end()));
    }

    void send_response(const std::vector<uint8_t>& data)
    {
      if (data.empty())
      {
        auto hdr = fmt::format("HTTP/1.1 204 No Content\r\n");
        send_raw(std::vector<uint8_t>(hdr.begin(), hdr.end()));
      }
      else
      {
        auto hdr = fmt::format(
          "HTTP/1.1 200 OK\r\n"
          "Content-Type: application/json\r\n"
          "Content-Length: {}\r\n\r\n",
          data.size());
        send_buffered(std::vector<uint8_t>(hdr.begin(), hdr.end()));
        send_buffered(data);
        flush();
      }
    }

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
          send_response(response.value());
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Exception while processing HTTP message: {}", e.what());
        send_response(fmt::format("Exception: {}", e.what()));

        // On any exception, close the connection.
        close();
      }
    }
  };

  class HTTPClientEndpoint : public HTTPEndpoint, public ClientEndpoint
  {
  public:
    HTTPClientEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint(HTTP_RESPONSE, session_id, writer_factory, std::move(ctx)),
      ClientEndpoint(session_id, writer_factory)
    {}

    void send_request(
      const std::string& path, const std::vector<uint8_t>& data) override
    {
      http::Request r(HTTP_POST);
      r.set_path(path);
      send_raw(r.build_request(data));
    }

    void send(const std::vector<uint8_t>& data) override
    {
      LOG_FATAL_FMT("send() should not be called directly on HTTPClient");
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
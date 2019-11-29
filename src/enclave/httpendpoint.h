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

    void send_response(
      const std::string& data,
      http_status status = HTTP_STATUS_OK,
      const std::string& content_type = "text/plain")
    {
      send_response(
        std::vector<uint8_t>(data.begin(), data.end()), status, content_type);
    }

    void send_response(
      const std::vector<uint8_t>& data,
      http_status status = HTTP_STATUS_OK,
      const std::string& content_type = "application/json")
    {
      if (data.empty() && status == HTTP_STATUS_OK)
      {
        status = HTTP_STATUS_NO_CONTENT;
      }

      if (status == HTTP_STATUS_NO_CONTENT)
      {
        const auto first_line = fmt::format(
          "HTTP/1.1 {} {}\r\n"
          "\r\n",
          status,
          http_status_str(status));

        send_raw(std::vector<uint8_t>(first_line.begin(), first_line.end()));
        return;
      }

      auto hdr = fmt::format(
        "HTTP/1.1 {} {}\r\n"
        "Content-Type: {}\r\n"
        "Content-Length: {}\r\n"
        "\r\n",
        status,
        http_status_str(status),
        content_type,
        data.size());
      send_buffered(std::vector<uint8_t>(hdr.begin(), hdr.end()));
      send_buffered(data);
      flush();
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
        const auto first_slash = path.find_first_of('/');
        const auto second_slash = path.find_first_of('/', first_slash + 1);

        constexpr auto path_parse_error =
          "Request path must contain '/[actor]/[method]'. Unable to parse "
          "'{}'.\n";

        if (
          first_slash != 0 || first_slash == std::string::npos ||
          second_slash == std::string::npos)
        {
          send_response(
            fmt::format(path_parse_error, path), HTTP_STATUS_BAD_REQUEST);
          return;
        }

        const auto actor_s = path.substr(first_slash + 1, second_slash - 1);
        const auto method_s = path.substr(second_slash + 1);

        if (actor_s.empty() || method_s.empty())
        {
          send_response(
            fmt::format(path_parse_error, path), HTTP_STATUS_BAD_REQUEST);
          return;
        }

        auto actor = rpc_map->resolve(actor_s);
        auto search = rpc_map->find(actor);
        if (actor == ccf::ActorsType::unknown || !search.has_value())
        {
          send_response(
            fmt::format("Unknown session '{}'.\n", actor_s),
            HTTP_STATUS_NOT_FOUND);
          return;
        }

        if (!search.value()->is_open())
        {
          send_response(
            fmt::format("Session '{}' is not open.\n", actor),
            HTTP_STATUS_NOT_FOUND);
          return;
        }

        const SessionContext session(session_id, peer_cert());
        RPCContext rpc_ctx(session);

        auto [success, json_rpc] = jsonrpc::unpack_rpc(body, rpc_ctx.pack);
        if (!success)
        {
          send_response(
            fmt::format("Unable to unpack body.\n"), HTTP_STATUS_BAD_REQUEST);
          return;
        }

        parse_rpc_context(rpc_ctx, json_rpc);
        // TODO: This is temporary; while we have a full RPC object inside the
        // body, it should match the dispatch details specified in the URI
        const auto expected = fmt::format("{}/{}", actor_s, method_s);
        if (rpc_ctx.method != expected)
        {
          send_response(
            fmt::format(
              "RPC method must match path ('{}' != '{}').\n",
              expected,
              rpc_ctx.method),
            HTTP_STATUS_BAD_REQUEST);
          return;
        }

        rpc_ctx.raw = body; // TODO: This is insufficient, need entire request
        rpc_ctx.method = method_s;
        rpc_ctx.actor = actor;

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
        send_response(
          fmt::format("Exception:\n{}\n", e.what()),
          HTTP_STATUS_INTERNAL_SERVER_ERROR);

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
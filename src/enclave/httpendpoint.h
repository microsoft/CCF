// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "clientendpoint.h"
#include "ds/logger.h"
#include "http_rpc_context.h"
#include "httpparser.h"
#include "rpcmap.h"
#include "wsupgrade.h"

namespace enclave
{
  class HTTPEndpoint : public TLSEndpoint, public http::MsgProcessor
  {
  protected:
    http::Parser p;
    bool is_websocket = false;

  public:
    HTTPEndpoint(
      http_parser_type parser_type,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(parser_type, *this)
    {}

    static void recv_cb(std::unique_ptr<enclave::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<HTTPEndpoint*>(msg->data.self.get())
        ->recv_(msg->data.data.data(), msg->data.data.size());
    }

    void recv(const uint8_t* data, size_t size) override
    {
      auto msg = std::make_unique<enclave::Tmsg<SendRecvMsg>>(&recv_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data.assign(data, data + size);

      enclave::ThreadMessaging::thread_messaging.add_task<SendRecvMsg>(
        execution_thread, std::move(msg));
    }

    void recv_(const uint8_t* data, size_t size)
    {
      recv_buffered(data, size);

      LOG_TRACE_FMT("recv called with {} bytes", size);

      if (!is_websocket)
      {
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

          try
          {
            if (p.execute(buf.data(), buf.size()) == 0)
            {
              LOG_FAIL_FMT("Failed to parse request");
              return;
            }
          }
          catch (const std::exception& e)
          {
            LOG_FAIL_FMT("Error parsing request: {}", e.what());
            return;
          }
        }
      }
      else
      {
        LOG_FAIL_FMT(
          "Receiving data after endpoint has been upgraded to websocket.");
        LOG_FAIL_FMT("Closing connection.");
        close();
      }
    }
  };

  class HTTPServerEndpoint : public HTTPEndpoint
  {
  private:
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RpcHandler> handler;
    size_t session_id;

    size_t request_index = 0;

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

    static void send_cb(std::unique_ptr<enclave::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<HTTPServerEndpoint*>(msg->data.self.get())
        ->send_(msg->data.data);
    }

    void send(const std::vector<uint8_t>& data) override
    {
      auto msg = std::make_unique<enclave::Tmsg<SendRecvMsg>>(&send_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data = data;

      enclave::ThreadMessaging::thread_messaging.add_task<SendRecvMsg>(
        execution_thread, std::move(msg));
    }

    void send_(const std::vector<uint8_t>& data)
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
        send_raw(http::Response(status).build_response({}, true));
        return;
      }

      auto response = http::Response(status);
      response.set_header("content-type", content_type);

      send_buffered(response.build_response(data, true));
      send_buffered(data);
      flush();
    }

    void handle_message(
      http_method verb,
      const std::string_view& path,
      const std::string_view& query,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body) override
    {
      LOG_TRACE_FMT(
        "Processing msg({}, {}, {}, [{} bytes])",
        http_method_str(verb),
        path,
        query,
        body.size());

      try
      {
        // Check if the client requested upgrade to websocket, and complete
        // handshake if necessary
        auto upgrade_resp =
          http::WebSocketUpgrader::upgrade_if_necessary(headers);
        if (upgrade_resp.has_value())
        {
          LOG_TRACE_FMT("Upgraded to websocket");
          is_websocket = true;
          send_raw(upgrade_resp.value());
          return;
        }

        const SessionContext session(session_id, peer_cert());

        std::shared_ptr<HttpRpcContext> rpc_ctx = nullptr;
        try
        {
          rpc_ctx = std::make_shared<HttpRpcContext>(
            session, verb, path, query, headers, body);
        }
        catch (std::exception& e)
        {
          send_response(e.what(), HTTP_STATUS_BAD_REQUEST);
        }

        rpc_ctx->set_request_index(request_index++);

        std::string_view actor_s = {};
        auto& method = rpc_ctx->remaining_path;

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

          actor_s = method.substr(first_slash + 1, second_slash - 1);
          method.remove_prefix(second_slash + 1);

          if (actor_s.empty() || method.empty())
          {
            send_response(
              fmt::format(path_parse_error, path), HTTP_STATUS_BAD_REQUEST);
            return;
          }
        }

        auto actor = rpc_map->resolve(std::string(actor_s));
        rpc_ctx->actor = actor;
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
            fmt::format("Session '{}' is not open.\n", actor_s),
            HTTP_STATUS_NOT_FOUND);
          return;
        }

        rpc_ctx->raw = body;

        auto response = search.value()->process(rpc_ctx);

        if (!response.has_value())
        {
          // If the RPC is pending, hold the connection.
          LOG_TRACE_FMT("Pending");
          return;
        }
        else
        {
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

    void handle_message(
      http_method method,
      const std::string_view& path,
      const std::string_view& query,
      const http::HeaderMap& headers,
      const std::vector<uint8_t>& body) override
    {
      handle_data_cb(body);

      close();
    }
  };
}
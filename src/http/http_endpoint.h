// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "enclave/client_endpoint.h"
#include "enclave/rpc_map.h"
#include "http_parser.h"
#include "http_rpc_context.h"
#include "ws_upgrade.h"

namespace http
{
  class HTTPEndpoint : public enclave::TLSEndpoint
  {
  protected:
    http::Parser& p;
    bool is_websocket = false;

    HTTPEndpoint(
      http::Parser& p_,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(p_)
    {}

  public:
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
        auto buf = read(4096, false);
        auto data = buf.data();
        auto size = buf.size();

        while (true)
        {
          if (size == 0)
          {
            return;
          }

          LOG_TRACE_FMT("Going to parse {} bytes", size);

          try
          {
            const auto used = p.execute(data, size);
            if (used == 0)
            {
              // Parsing error
              LOG_FAIL_FMT("Failed to parse request");
              return;
            }
            else if (used > size)
            {
              // Something has gone very wrong
              LOG_FAIL_FMT(
                "Unexpected return result - tried to parse {} bytes, actually "
                "parsed {}",
                size,
                used);
              return;
            }
            else if (used == size)
            {
              // Used all provided bytes - check if more are available
              buf = read(4096, false);
              data = buf.data();
              size = buf.size();
            }
            else
            {
              // Used some bytes - pass over these and retry with remainder
              data += used;
              size -= used;
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

  class HTTPServerEndpoint : public HTTPEndpoint, public http::RequestProcessor
  {
  private:
    http::RequestParser request_parser;

    std::shared_ptr<enclave::RPCMap> rpc_map;
    std::shared_ptr<enclave::RpcHandler> handler;
    std::shared_ptr<enclave::SessionContext> session_ctx;
    size_t session_id;
    size_t request_index = 0;

  public:
    HTTPServerEndpoint(
      std::shared_ptr<enclave::RPCMap> rpc_map,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint(request_parser, session_id, writer_factory, std::move(ctx)),
      request_parser(*this),
      rpc_map(rpc_map),
      session_id(session_id)
    {}

    void send(const std::vector<uint8_t>& data) override
    {
      send_raw(data);
    }

    void send_response(
      const std::string& data,
      http_status status = HTTP_STATUS_OK,
      const std::string& content_type = http::headervalues::contenttype::TEXT)
    {
      send_response(
        std::vector<uint8_t>(data.begin(), data.end()), status, content_type);
    }

    void send_response(
      const std::vector<uint8_t>& data,
      http_status status = HTTP_STATUS_OK,
      const std::string& content_type = http::headervalues::contenttype::JSON)
    {
      if (data.empty() && status == HTTP_STATUS_OK)
      {
        status = HTTP_STATUS_NO_CONTENT;
      }

      auto response = http::Response(status);

      if (status == HTTP_STATUS_NO_CONTENT)
      {
        send_raw(response.build_response(true));
        return;
      }

      response.set_header(http::headers::CONTENT_TYPE, content_type);
      response.set_body(&data);

      send_raw(response.build_response(true));
      send_raw(data);
    }

    void handle_request(
      http_method verb,
      const std::string_view& path,
      const std::string& query,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
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

        if (session_ctx == nullptr)
        {
          session_ctx =
            std::make_shared<enclave::SessionContext>(session_id, peer_cert());
        }

        std::shared_ptr<HttpRpcContext> rpc_ctx = nullptr;
        try
        {
          rpc_ctx = std::make_shared<HttpRpcContext>(
            request_index++,
            session_ctx,
            verb,
            path,
            query,
            std::move(headers),
            std::move(body));
        }
        catch (std::exception& e)
        {
          send_response(e.what(), HTTP_STATUS_BAD_REQUEST);
        }

        const auto actor_opt = http::extract_actor(*rpc_ctx);
        if (!actor_opt.has_value())
        {
          send_response(fmt::format(
            "Request path must contain '/[actor]/[method]'. Unable to parse "
            "'{}'.\n",
            rpc_ctx->get_method()));
          return;
        }

        const auto& actor_s = actor_opt.value();
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
            fmt::format("Session '{}' is not open.\n", actor_s),
            HTTP_STATUS_NOT_FOUND);
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
          send_buffered(response.value());
          flush();
        }
      }
      catch (const std::exception& e)
      {
        send_response(
          fmt::format("Exception:\n{}\n", e.what()),
          HTTP_STATUS_INTERNAL_SERVER_ERROR);

        // On any exception, close the connection.
        LOG_TRACE_FMT("Closing connection due to exception: {}", e.what());
        close();
        throw;
      }
    }
  };

  class HTTPClientEndpoint : public HTTPEndpoint,
                             public enclave::ClientEndpoint,
                             public http::ResponseProcessor
  {
  private:
    http::ResponseParser response_parser;

  public:
    HTTPClientEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint(response_parser, session_id, writer_factory, std::move(ctx)),
      ClientEndpoint(session_id, writer_factory),
      response_parser(*this)
    {}

    void send_request(const std::vector<uint8_t>& data) override
    {
      send_raw(data);
    }

    void send(const std::vector<uint8_t>& data) override
    {
      throw std::logic_error(
        "send() should not be called directly on HTTPClient");
    }

    void handle_response(
      http_status status,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      handle_data_cb(status, std::move(headers), std::move(body));

      LOG_TRACE_FMT("Closing connection, message handled");
      close();
    }
  };
}
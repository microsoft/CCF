// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "enclave/client_endpoint.h"
#include "enclave/rpc_map.h"
#include "http_parser.h"
#include "http_rpc_context.h"
#include "ws_parser.h"
#include "ws_rpc_context.h"
#include "ws_upgrade.h"

namespace http
{
  class HTTPEndpoint : public enclave::TLSEndpoint
  {
  protected:
    http::Parser& p;
    ws::Parser& wp;
    bool is_websocket = false;
    size_t ws_next_read = ws::INITIAL_READ;

    HTTPEndpoint(
      http::Parser& p_,
      ws::Parser& wp_,
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(p_),
      wp(wp_)
    {}

  public:
    static void recv_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<HTTPEndpoint*>(msg->data.self.get())
        ->recv_(msg->data.data.data(), msg->data.data.size());
    }

    void recv(const uint8_t* data, size_t size) override
    {
      auto msg = std::make_unique<threading::Tmsg<SendRecvMsg>>(&recv_cb);
      msg->data.self = this->shared_from_this();
      msg->data.data.assign(data, data + size);

      threading::ThreadMessaging::thread_messaging.add_task(
        execution_thread, std::move(msg));
    }

    void recv_(const uint8_t* data_, size_t size_)
    {
      recv_buffered(data_, size_);

      LOG_TRACE_FMT("recv called with {} bytes", size_);

      if (is_websocket)
      {
        std::vector<uint8_t> buf(ws_next_read);
        while (true)
        {
          if (ws_next_read > buf.size())
          {
            buf.resize(ws_next_read);
          }

          auto r = read(buf.data(), ws_next_read, true);
          if (r == 0)
          {
            return;
          }
          else
          {
            try
            {
              ws_next_read = wp.consume(buf.data(), r);
            }
            catch (const std::exception& e)
            {
              LOG_DEBUG_FMT("Error parsing WebSocket request: {}", e.what());
              close();
              return;
            }

            if (!ws_next_read)
            {
              close();
              return;
            }
          }
        }
      }
      else
      {
        constexpr auto read_block_size = 4096;
        std::vector<uint8_t> buf(read_block_size);
        auto data = buf.data();
        auto n_read = read(data, buf.size(), false);

        while (true)
        {
          if (n_read == 0)
          {
            return;
          }

          LOG_TRACE_FMT("Going to parse {} bytes", n_read);

          try
          {
            p.execute(data, n_read);

            // Used all provided bytes - check if more are available
            n_read = read(buf.data(), buf.size(), false);
          }
          catch (const std::exception& e)
          {
            LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());
            close();
            break;
          }
        }
      }
    }
  };

  class HTTPServerEndpoint : public HTTPEndpoint, public http::RequestProcessor
  {
  private:
    http::RequestParser request_parser;
    ws::RequestParser ws_request_parser;

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
      HTTPEndpoint(
        request_parser,
        ws_request_parser,
        session_id,
        writer_factory,
        std::move(ctx)),
      request_parser(*this),
      ws_request_parser(*this),
      rpc_map(rpc_map),
      session_id(session_id)
    {}

    void send(std::vector<uint8_t>&& data) override
    {
      send_raw(std::move(data));
    }

    void handle_request(
      llhttp_method verb,
      const std::string_view& path,
      const std::string& query,
      const std::string&,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      LOG_TRACE_FMT(
        "Processing msg({}, {}, {}, [{} bytes])",
        llhttp_method_name(verb),
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
          send_raw(std::move(upgrade_resp.value()));
          return;
        }

        if (session_ctx == nullptr)
        {
          session_ctx =
            std::make_shared<enclave::SessionContext>(session_id, peer_cert());
        }

        std::shared_ptr<enclave::RpcContext> rpc_ctx = nullptr;
        try
        {
          if (is_websocket)
          {
            rpc_ctx = std::make_shared<ws::WsRpcContext>(
              request_index++, session_ctx, path, std::move(body));
          }
          else
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
        }
        catch (std::exception& e)
        {
          if (is_websocket)
          {
            send_raw(ws::error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              e.what()));
          }
          else
          {
            send_raw(http::error(
              HTTP_STATUS_INTERNAL_SERVER_ERROR,
              ccf::errors::InternalError,
              e.what()));
          }
        }

        const auto actor_opt = http::extract_actor(*rpc_ctx);
        if (!actor_opt.has_value())
        {
          rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format(
              "Request path must contain '/[actor]/[method]'. Unable to parse "
              "'{}'.",
              rpc_ctx->get_method()));
          send_raw(rpc_ctx->serialise_response());
          return;
        }

        const auto& actor_s = actor_opt.value();
        auto actor = rpc_map->resolve(actor_s);
        auto search = rpc_map->find(actor);
        if (actor == ccf::ActorsType::unknown || !search.has_value())
        {
          rpc_ctx->set_error(
            HTTP_STATUS_NOT_FOUND,
            ccf::errors::ResourceNotFound,
            fmt::format("Unknown actor '{}'.", actor_s));
          send_raw(rpc_ctx->serialise_response());
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
        if (is_websocket)
        {
          send_raw(ws::error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Exception: {}", e.what())));
        }
        else
        {
          send_raw(http::error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Exception: {}", e.what())));
        }

        // On any exception, close the connection.
        LOG_FAIL_FMT("Closing connection");
        LOG_DEBUG_FMT("Closing connection due to exception: {}", e.what());
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
    ws::ResponseParser ws_response_parser;

  public:
    HTTPClientEndpoint(
      size_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint(
        response_parser,
        ws_response_parser,
        session_id,
        writer_factory,
        std::move(ctx)),
      ClientEndpoint(session_id, writer_factory),
      response_parser(*this),
      ws_response_parser(*this)
    {}

    void send_request(std::vector<uint8_t>&& data) override
    {
      send_raw(std::move(data));
    }

    void send(std::vector<uint8_t>&&) override
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

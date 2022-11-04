// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "enclave/client_endpoint.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http2.h"
#include "http_rpc_context.h"

namespace http
{
  class HTTP2Endpoint : public ccf::TLSEndpoint
  {
  protected:
    http2::Session& session;

    HTTP2Endpoint(
      http2::Session& session_,
      int64_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      session(session_)
    {}

  public:
    static void recv_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<HTTP2Endpoint*>(msg->data.self.get())
        ->recv_(msg->data.data.data(), msg->data.data.size());
    }

    void recv(const uint8_t* data, size_t size, sockaddr) override
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
          session.recv(data, n_read);

          // Used all provided bytes - check if more are available
          n_read = read(buf.data(), buf.size(), false);
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT("Error parsing HTTP request");
          LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

          auto response = http::Response(HTTP_STATUS_BAD_REQUEST);
          response.set_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto body = fmt::format(
            "Unable to parse data as a HTTP request. Error details are "
            "below.\n\n{}",
            e.what());
          response.set_body((const uint8_t*)body.data(), body.size());
          send_raw(response.build_response());

          close();
          break;
        }
      }
    }
  };

  class HTTP2ServerEndpoint : public HTTP2Endpoint,
                              public RequestProcessor,
                              public AbstractClientStreamer
  {
  private:
    http2::ServerSession server_session;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    int64_t session_id;
    ccf::ListenInterfaceID interface_id;

  public:
    HTTP2ServerEndpoint(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      int64_t session_id,
      const ccf::ListenInterfaceID& interface_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx,
      const http::ParserConfiguration&
        configuration, // Note: Support configuration
      const std::shared_ptr<ErrorReporter>& error_reporter =
        nullptr) // Note: Report errors
      :
      HTTP2Endpoint(server_session, session_id, writer_factory, std::move(ctx)),
      server_session(*this, *this),
      rpc_map(rpc_map),
      session_id(session_id),
      interface_id(interface_id)
    {}

    void send(std::vector<uint8_t>&& data, sockaddr) override
    {
      send_raw(std::move(data));
    }

    void stream(std::vector<uint8_t>&& data, int32_t stream_id) override
    {
      LOG_FAIL_FMT("Streaming data: {}", data.size());
      server_session.send_data(stream_id, std::move(data));
    }

    void handle_request(
      llhttp_method verb,
      const std::string_view& url,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body,
      int32_t stream_id) override
    {
      LOG_TRACE_FMT(
        "Processing msg({}, {} [{} bytes])",
        llhttp_method_name(verb),
        url,
        body.size());

      try
      {
        if (session_ctx == nullptr)
        {
          session_ctx = std::make_shared<ccf::SessionContext>(
            session_id, peer_cert(), interface_id);
        }

        std::shared_ptr<http::HttpRpcContext> rpc_ctx = nullptr;
        try
        {
          rpc_ctx = std::make_shared<HttpRpcContext>(
            session_ctx, verb, url, std::move(headers), std::move(body));
          rpc_ctx->set_client_streamer(this, stream_id);
        }
        catch (std::exception& e)
        {
          // Note: return HTTP_STATUS_INTERNAL_SERVER_ERROR, e.what()
        }

        const auto actor_opt = http::extract_actor(*rpc_ctx);
        std::optional<std::shared_ptr<ccf::RpcHandler>> search;
        ccf::ActorsType actor = ccf::ActorsType::unknown;
        if (actor_opt.has_value())
        {
          const auto& actor_s = actor_opt.value();
          actor = rpc_map->resolve(actor_s);
          search = rpc_map->find(actor);
        }
        if (
          !actor_opt.has_value() || actor == ccf::ActorsType::unknown ||
          !search.has_value())
        {
          // if there is no actor, proceed with the "app" as the ActorType and
          // process the request
          search = rpc_map->find(ccf::ActorsType::users);
        }

        search.value()->process(rpc_ctx);

        if (rpc_ctx->is_streaming)
        {
          // TODO: Add support for streaming before initial response is set!
          server_session.set_no_unary(stream_id);
        }

        if (rpc_ctx->response_is_pending)
        {
          // If the RPC is pending, hold the connection.
          LOG_TRACE_FMT("Pending");
          return;
        }
        else
        {
          server_session.send_response(
            stream_id,
            rpc_ctx->get_response_http_status(),
            rpc_ctx->get_response_headers(),
            rpc_ctx->get_response_trailers(),
            std::move(rpc_ctx->get_response_body()));
        }
      }
      catch (const std::exception& e)
      {
        // Note: return HTTP_STATUS_INTERNAL_SERVER_ERROR, e.what()
        send_raw(http::error(
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Exception: {}", e.what())));

        // On any exception, close the connection.
        LOG_FAIL_FMT("Closing connection");
        LOG_DEBUG_FMT("Closing connection due to exception: {}", e.what());
        close();
        throw;
      }
    }
  };

  class HTTP2ClientEndpoint : public HTTP2Endpoint,
                              public ccf::ClientEndpoint,
                              public http::ResponseProcessor
  {
  private:
    http2::ClientSession client_session;

  public:
    HTTP2ClientEndpoint(
      int64_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTP2Endpoint(client_session, session_id, writer_factory, std::move(ctx)),
      ClientEndpoint(session_id, writer_factory),
      client_session(*this, *this)
    {}

    void send_request(const http::Request& request) override
    {
      // Note: Avoid extra copy
      std::vector<uint8_t> request_body = {
        request.get_content_data(),
        request.get_content_data() + request.get_content_length()};
      client_session.send_structured_request(
        request.get_method(),
        request.get_path(),
        request.get_headers(),
        std::move(request_body));
    }

    void send(std::vector<uint8_t>&& data, sockaddr) override
    {
      send_raw(std::move(data));
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

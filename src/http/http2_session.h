// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "enclave/client_session.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http2.h"
#include "http_rpc_context.h"

namespace http
{
  struct HTTP2SessionContext : public ccf::SessionContext
  {
    int32_t stream_id;

    using SessionContext::SessionContext;
  };

  class HTTP2Session : public ccf::TLSSession
  {
  protected:
    http2::Parser& parser;

    HTTP2Session(
      http2::Parser& parser_,
      int64_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      TLSSession(session_id, writer_factory, std::move(ctx)),
      parser(parser_)
    {}

  public:
    void receive_data(const uint8_t* data_, size_t size_) override
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
          parser.execute(data, n_read);

          // Used all provided bytes - check if more are available
          n_read = read(buf.data(), buf.size(), false);
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT("Error parsing HTTP request");
          LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

          http::HeaderMap headers;
          headers[http::headers::CONTENT_TYPE] =
            http::headervalues::contenttype::TEXT;

          auto body = fmt::format(
            "Unable to parse data as a HTTP request. Error details are "
            "below.\n\n{}",
            e.what());

          // TODO: Avoid copy
          std::vector<uint8_t> data(body.begin(), body.end());
          send_response(HTTP_STATUS_BAD_REQUEST, std::move(headers), data);

          close();
          break;
        }
      }
    }
  };

  class HTTP2ServerSession : public HTTP2Session, public http::RequestProcessor
  {
  private:
    http2::ServerParser server_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    int64_t session_id;
    ccf::ListenInterfaceID interface_id;

  public:
    HTTP2ServerSession(
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
      HTTP2Session(server_parser, session_id, writer_factory, std::move(ctx)),
      server_parser(*this, *this),
      rpc_map(rpc_map),
      session_id(session_id),
      interface_id(interface_id)
    {}

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
          auto http2_session_ctx = std::make_shared<HTTP2SessionContext>(
            session_id, peer_cert(), interface_id);
          http2_session_ctx->stream_id = stream_id;
          session_ctx = http2_session_ctx;
        }

        // TODO: Yuck! Where should the stream_id live!?
        {
          auto http2_session_ctx =
            std::dynamic_pointer_cast<HTTP2SessionContext>(session_ctx);
          if (http2_session_ctx == nullptr)
          {
            throw std::logic_error("WRONG SESSION TYPE!");
          }
          if (http2_session_ctx->stream_id != stream_id)
          {
            // Make a new one, with the right stream_id!
            // Real wasteful!!!
            auto http2_session_ctx = std::make_shared<HTTP2SessionContext>(
              session_id, peer_cert(), interface_id);
            http2_session_ctx->stream_id = stream_id;
            session_ctx = http2_session_ctx;
          }
        }

        std::shared_ptr<http::HttpRpcContext> rpc_ctx = nullptr;
        try
        {
          rpc_ctx = std::make_shared<HttpRpcContext>(
            session_ctx, verb, url, std::move(headers), std::move(body));
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

        if (rpc_ctx->response_is_pending)
        {
          // If the RPC is pending, hold the connection.
          LOG_TRACE_FMT("Pending");
          return;
        }
        else
        {
          server_parser.send_response(
            stream_id,
            rpc_ctx->get_response_http_status(),
            rpc_ctx->get_response_headers(),
            rpc_ctx->get_response_trailers(),
            std::move(rpc_ctx->get_response_body()));
        }
      }
      catch (const std::exception& e)
      {
        // TODO: This doesn't exist?
        send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Exception: {}", e.what())});

        // On any exception, close the connection.
        LOG_FAIL_FMT("Closing connection");
        LOG_DEBUG_FMT("Closing connection due to exception: {}", e.what());
        close();
        throw;
      }
    }

    void send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      std::span<const uint8_t> body) override
    {
      throw std::logic_error("Unimplemented");
    }

    void send_response(
      int32_t stream_id,
      http_status status_code,
      http::HeaderMap&& headers,
      std::span<const uint8_t> body) override
    {
      server_parser.send_response(
        stream_id,
        status_code,
        std::move(headers),
        {}, // TODO: Include trailers
        {body.begin(), body.end()} // TODO: Remove copy
      );
    }
  };

  class HTTP2ClientSession : public HTTP2Session,
                             public ccf::ClientSession,
                             public http::ResponseProcessor
  {
  private:
    http2::ClientParser client_parser;

  public:
    HTTP2ClientSession(
      int64_t session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTP2Session(client_parser, session_id, writer_factory, std::move(ctx)),
      ccf::ClientSession(session_id, writer_factory),
      client_parser(*this, *this)
    {}

    void send_request(http::Request&& request) override
    {
      // Note: Avoid extra copy
      std::vector<uint8_t> request_body = {
        request.get_content_data(),
        request.get_content_data() + request.get_content_length()};
      client_parser.send_structured_request(
        request.get_method(),
        request.get_path(),
        request.get_headers(),
        std::move(request_body));
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

    void send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      std::span<const uint8_t> body) override
    {
      throw std::logic_error("Unimplemented");
    }
  };
}

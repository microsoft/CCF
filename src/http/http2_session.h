// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "enclave/client_session.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http2_parser.h"
#include "http_responder.h"
#include "http_rpc_context.h"

namespace http
{
  struct HTTP2SessionContext : public ccf::SessionContext
  {
    int32_t stream_id;

    using SessionContext::SessionContext;
  };

  class HTTP2Session : public ccf::ThreadedSession
  {
  protected:
    std::shared_ptr<ccf::TLSSession> tls_io;
    tls::ConnID session_id;

    HTTP2Session(
      tls::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      ccf::ThreadedSession(session_id_),
      tls_io(std::make_shared<ccf::TLSSession>(
        session_id_, writer_factory, std::move(ctx))),
      session_id(session_id_)
    {}

  public:
    virtual bool parse(std::span<const uint8_t> data) = 0;

    // TODO: Is this even needed?
    void send_data(std::span<const uint8_t> data) override
    {
      tls_io->send_raw(data.data(), data.size());
    }

    void handle_incoming_data_thread(std::span<const uint8_t> data) override
    {
      tls_io->recv_buffered(data.data(), data.size());

      LOG_TRACE_FMT("recv called with {} bytes", data.size());

      constexpr auto read_block_size = 4096;
      std::vector<uint8_t> buf(read_block_size);
      auto n_read = tls_io->read(buf.data(), buf.size(), false);

      while (true)
      {
        if (n_read == 0)
        {
          return;
        }

        LOG_TRACE_FMT("Going to parse {} bytes", n_read);

        bool cont = parse({buf.data(), n_read});
        if (!cont)
        {
          return;
        }

        // Used all provided bytes - check if more are available
        n_read = tls_io->read(buf.data(), buf.size(), false);
      }
    }
  };

  class HTTP2StreamResponder : public http::HTTPResponder
  {
  private:
    http2::StreamId stream_id;
    http2::ServerParser& server_parser;

  public:
    HTTP2StreamResponder(
      http2::StreamId stream_id_, http2::ServerParser& server_parser_) :
      stream_id(stream_id_),
      server_parser(server_parser_)
    {}

    void send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      http::HeaderMap&& trailers,
      std::span<const uint8_t> body) override
    {
      server_parser.respond(
        stream_id, status_code, std::move(headers), std::move(trailers), body);
    }
  };

  class HTTP2ServerSession : public HTTP2Session,
                             public http::RequestProcessor,
                             public http::HTTPResponder
  // TODO: This is both a Responder, and a collection of Responders. Its
  // implementation passes off to the default stream 0. This seems wrong
  {
  private:
    http2::ServerParser server_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    ccf::ListenInterfaceID interface_id;

    std::unordered_map<http2::StreamId, std::shared_ptr<HTTP2StreamResponder>>
      responders;

    std::shared_ptr<HTTP2StreamResponder> get_stream_responder(
      http2::StreamId stream_id)
    {
      auto it = responders.find(stream_id);
      if (it == responders.end())
      {
        it = responders.emplace_hint(
          it,
          std::make_pair(
            stream_id,
            std::make_shared<HTTP2StreamResponder>(stream_id, server_parser)));
      }

      return it->second;
    }

  public:
    HTTP2ServerSession(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      int64_t session_id_,
      const ccf::ListenInterfaceID& interface_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx,
      const http::ParserConfiguration&
        configuration, // Note: Support configuration
      const std::shared_ptr<ErrorReporter>& error_reporter =
        nullptr) // Note: Report errors
      :
      HTTP2Session(session_id_, writer_factory, std::move(ctx)),
      server_parser(*this),
      rpc_map(rpc_map),
      interface_id(interface_id)
    {
      server_parser.set_outgoing_data_handler(
        [this](std::span<const uint8_t> data) {
          this->tls_io->send_raw(data.data(), data.size());
        });
    }

    bool parse(std::span<const uint8_t> data) override
    {
      try
      {
        server_parser.execute(data.data(), data.size());
        return true;
      }
      catch (const std::exception& e)
      {
        LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

        http::HeaderMap headers;
        headers[http::headers::CONTENT_TYPE] =
          http::headervalues::contenttype::TEXT;

        auto body = fmt::format(
          "Unable to parse data as a HTTP request. Error details are "
          "below.\n\n{}",
          e.what());

        // NB: If we have an error where we don't know a stream ID, we respond
        // on the default stream
        send_response(
          HTTP_STATUS_BAD_REQUEST,
          std::move(headers),
          {},
          {(const uint8_t*)body.data(), body.size()});

        tls_io->close();
      }
      return false;
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

      auto responder = get_stream_responder(stream_id);

      try
      {
        if (session_ctx == nullptr)
        {
          auto http2_session_ctx = std::make_shared<HTTP2SessionContext>(
            session_id, tls_io->peer_cert(), interface_id);
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
              session_id, tls_io->peer_cert(), interface_id);
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
          // TODO: return HTTP_STATUS_INTERNAL_SERVER_ERROR, e.what()
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
          responder->send_response(
            rpc_ctx->get_response_http_status(),
            rpc_ctx->get_response_headers(),
            rpc_ctx->get_response_trailers(),
            std::move(rpc_ctx->get_response_body()));
        }
      }
      catch (const std::exception& e)
      {
        responder->send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_INTERNAL_SERVER_ERROR,
          ccf::errors::InternalError,
          fmt::format("Exception: {}", e.what())});

        // On any exception, close the connection.
        LOG_FAIL_FMT("Closing connection");
        LOG_DEBUG_FMT("Closing connection due to exception: {}", e.what());
        tls_io->close();
        throw;
      }
    }

    void send_response(
      http_status status_code,
      http::HeaderMap&& headers,
      http::HeaderMap&& trailers,
      std::span<const uint8_t> body) override
    {
      get_stream_responder(http::DEFAULT_STREAM_ID)
        ->send_response(
          status_code, std::move(headers), std::move(trailers), body);
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
      int64_t session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTP2Session(session_id_, writer_factory, std::move(ctx)),
      ccf::ClientSession(session_id_, writer_factory),
      client_parser(*this)
    {
      client_parser.set_outgoing_data_handler(
        [this](std::span<const uint8_t> data) {
          this->tls_io->send_raw(data.data(), data.size());
        });
    }

    bool parse(std::span<const uint8_t> data) override
    {
      // Catch response parsing errors and log them
      try
      {
        client_parser.execute(data.data(), data.size());

        return true;
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Error parsing HTTP2 response on session {}", session_id);
        LOG_DEBUG_FMT("Error parsing HTTP2 response: {}", e.what());
        LOG_DEBUG_FMT(
          "Error occurred while parsing fragment {} byte fragment:\n{}",
          data.size(),
          std::string_view(data.begin(), data.end()));

        tls_io->close();
      }
      return false;
    }

    void send_request(http::Request&& request) override
    {
      client_parser.send_structured_request(
        request.get_method(),
        request.get_path(),
        request.get_headers(),
        {request.get_content_data(), request.get_content_length()});
    }

    void handle_response(
      http_status status,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      handle_data_cb(status, std::move(headers), std::move(body));

      LOG_TRACE_FMT("Closing connection, message handled");
      tls_io->close();
    }
  };
}

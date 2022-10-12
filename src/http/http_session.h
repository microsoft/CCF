// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "enclave/client_session.h"
#include "enclave/rpc_handler.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http_parser.h"
#include "http_responder.h"
#include "http_rpc_context.h"

namespace http
{
  class HTTPSession : public ccf::ThreadedSession
  {
  protected:
    std::shared_ptr<ccf::TLSSession> tls_io;
    std::shared_ptr<ErrorReporter> error_reporter;
    tls::ConnID session_id;

    HTTPSession(
      tls::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx,
      const std::shared_ptr<ErrorReporter>& error_reporter = nullptr) :
      ccf::ThreadedSession(session_id_),
      tls_io(std::make_shared<ccf::TLSSession>(
        session_id_, writer_factory, std::move(ctx))),
      error_reporter(error_reporter),
      session_id(session_id_)
    {}

  public:
    virtual bool parse(std::span<const uint8_t> data) = 0;

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

  class HTTPServerSession : public HTTPSession,
                            public http::RequestProcessor,
                            public http::HTTPResponder
  {
  private:
    http::RequestParser request_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    ccf::ListenInterfaceID interface_id;

  public:
    HTTPServerSession(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      tls::ConnID session_id_,
      const ccf::ListenInterfaceID& interface_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx,
      const http::ParserConfiguration& configuration,
      const std::shared_ptr<ErrorReporter>& error_reporter = nullptr) :
      HTTPSession(session_id_, writer_factory, std::move(ctx), error_reporter),
      request_parser(*this, configuration),
      rpc_map(rpc_map),
      interface_id(interface_id)
    {}

    bool parse(std::span<const uint8_t> data) override
    {
      // Catch request parsing errors and convert them to error responses
      try
      {
        request_parser.execute(data.data(), data.size());

        return true;
      }
      catch (RequestPayloadTooLarge& e)
      {
        if (error_reporter)
        {
          error_reporter->report_request_payload_too_large_error(session_id);
        }

        LOG_DEBUG_FMT("Request is too large: {}", e.what());

        send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_PAYLOAD_TOO_LARGE,
          ccf::errors::RequestBodyTooLarge,
          e.what()});

        tls_io->close();
      }
      catch (RequestHeaderTooLarge& e)
      {
        if (error_reporter)
        {
          error_reporter->report_request_header_too_large_error(session_id);
        }

        LOG_DEBUG_FMT("Request header is too large: {}", e.what());

        send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
          ccf::errors::RequestHeaderTooLarge,
          e.what()});

        tls_io->close();
      }
      catch (const std::exception& e)
      {
        if (error_reporter)
        {
          error_reporter->report_parsing_error(session_id);
        }
        LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

        http::HeaderMap headers;
        headers[http::headers::CONTENT_TYPE] =
          http::headervalues::contenttype::TEXT;

        // NB: Avoid formatting input data a string, as it may contain null
        // bytes. Instead insert it at the end of this message, verbatim
        auto body_s = fmt::format(
          "Unable to parse data as a HTTP request. Error message is: {}\n"
          "Error occurred while parsing fragment:\n",
          e.what());
        std::vector<uint8_t> response_body(
          std::begin(body_s), std::end(body_s));
        response_body.insert(response_body.end(), data.begin(), data.end());

        send_response(
          HTTP_STATUS_BAD_REQUEST, std::move(headers), {}, response_body);

        tls_io->close();
      }

      return false;
    }

    void handle_request(
      llhttp_method verb,
      const std::string_view& url,
      http::HeaderMap&& headers,
      std::vector<uint8_t>&& body,
      int32_t) override
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
            session_id, tls_io->peer_cert(), interface_id);
        }

        std::shared_ptr<http::HttpRpcContext> rpc_ctx = nullptr;
        try
        {
          rpc_ctx = std::make_shared<HttpRpcContext>(
            session_ctx, verb, url, std::move(headers), std::move(body));
        }
        catch (std::exception& e)
        {
          send_odata_error_response(ccf::ErrorDetails{
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error constructing RpcContext: {}", e.what())});
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
          send_response(
            rpc_ctx->get_response_http_status(),
            rpc_ctx->get_response_headers(),
            rpc_ctx->get_response_trailers(),
            std::move(rpc_ctx->get_response_body()));
        }
      }
      catch (const std::exception& e)
      {
        send_odata_error_response(ccf::ErrorDetails{
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
      if (!trailers.empty())
      {
        throw std::logic_error("Cannot return trailers over HTTP/1");
      }

      auto response = http::Response(status_code);
      for (const auto& [k, v] : headers)
      {
        response.set_header(k, v);
      }
      response.set_body(body.data(), body.size());

      auto data = response.build_response();
      tls_io->send_raw(data.data(), data.size());
    }
  };

  class HTTPClientSession : public HTTPSession,
                            public ccf::ClientSession,
                            public http::ResponseProcessor
  {
  private:
    http::ResponseParser response_parser;

  public:
    HTTPClientSession(
      tls::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPSession(session_id_, writer_factory, std::move(ctx)),
      ClientSession(session_id_, writer_factory),
      response_parser(*this)
    {}

    bool parse(std::span<const uint8_t> data) override
    {
      // Catch response parsing errors and log them
      try
      {
        response_parser.execute(data.data(), data.size());

        return true;
      }
      catch (const std::exception& e)
      {
        if (error_reporter)
        {
          error_reporter->report_parsing_error(session_id);
        }
        LOG_FAIL_FMT("Error parsing HTTP response on session {}", session_id);
        LOG_DEBUG_FMT("Error parsing HTTP response: {}", e.what());
        LOG_DEBUG_FMT(
          "Error occurred while parsing fragment {} byte fragment:\n{}",
          data.size(),
          std::string_view((char const*)data.data(), data.size()));

        tls_io->close();
      }
      return false;
    }

    void send_request(http::Request&& request) override
    {
      auto data = request.build_request();
      tls_io->send_raw(data.data(), data.size());
    }

    void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f,
      const HandleErrorCallback e) override
    {
      tls_io->set_handshake_error_cb([e](std::string&& error_msg) {
        if (e)
        {
          e(error_msg);
        }
        else
        {
          LOG_FAIL_FMT("{}", error_msg);
        }
      });

      ccf::ClientSession::connect(hostname, service, f, e);
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

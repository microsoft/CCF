// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "enclave/client_session.h"
#include "enclave/rpc_handler.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http_parser.h"
#include "http_rpc_context.h"

namespace http
{
  class HTTPEndpoint : public ccf::TLSSession
  {
  protected:
    http::Parser& p;
    std::shared_ptr<ErrorReporter> error_reporter;

    HTTPEndpoint(
      http::Parser& p_,
      tls::ConnID session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx,
      const std::shared_ptr<ErrorReporter>& error_reporter = nullptr) :
      TLSSession(session_id, writer_factory, std::move(ctx)),
      p(p_),
      error_reporter(error_reporter)
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
          p.execute(data, n_read);

          // Used all provided bytes - check if more are available
          n_read = read(buf.data(), buf.size(), false);
        }
        catch (RequestPayloadTooLarge& e)
        {
          if (error_reporter)
          {
            error_reporter->report_request_payload_too_large_error(session_id);
          }

          LOG_DEBUG_FMT("Request is too large: {}", e.what());

          // TODO: Don't pre-serialise here
          send_odata_error_response(ccf::ErrorDetails{
            HTTP_STATUS_PAYLOAD_TOO_LARGE,
            ccf::errors::RequestBodyTooLarge,
            e.what()});

          close();
          break;
        }
        catch (RequestHeaderTooLarge& e)
        {
          if (error_reporter)
          {
            error_reporter->report_request_header_too_large_error(session_id);
          }

          LOG_DEBUG_FMT("Request header is too large: {}", e.what());

          // TODO: Don't pre-serialise here
          send_odata_error_response(ccf::ErrorDetails{
            HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
            ccf::errors::RequestHeaderTooLarge,
            e.what()});

          close();
          break;
        }
        catch (const std::exception& e)
        {
          if (error_reporter)
          {
            error_reporter->report_parsing_error(session_id);
          }
          LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

          auto response = http::Response(HTTP_STATUS_BAD_REQUEST);
          response.set_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          // NB: Avoid formatting input data a string, as it may contain null
          // bytes. Instead insert it at the end of this message, verbatim
          auto body_s = fmt::format(
            "Unable to parse data as a HTTP request. Error message is: {}\n"
            "Error occurred while parsing fragment:\n",
            e.what());
          std::vector<uint8_t> response_body(
            std::begin(body_s), std::end(body_s));
          response_body.insert(response_body.end(), data, data + n_read);
          response.set_body(response_body.data(), response_body.size());
          // TODO: Don't pre-serialise here
          send_response(std::move(response));

          close();
          break;
        }
      }
    }
  };

  class HTTPServerSession : public HTTPEndpoint, public http::RequestProcessor
  {
  private:
    http::RequestParser request_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    tls::ConnID session_id;
    ccf::ListenInterfaceID interface_id;

  public:
    HTTPServerSession(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      tls::ConnID session_id,
      const ccf::ListenInterfaceID& interface_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx,
      const http::ParserConfiguration& configuration,
      const std::shared_ptr<ErrorReporter>& error_reporter = nullptr) :
      HTTPEndpoint(
        request_parser,
        session_id,
        writer_factory,
        std::move(ctx),
        error_reporter),
      request_parser(*this, configuration),
      rpc_map(rpc_map),
      session_id(session_id),
      interface_id(interface_id)
    {}

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
            session_id, peer_cert(), interface_id);
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
            e.what()});
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
          // TODO: Don't pre-serialise!
          ccf::Session::send_data(rpc_ctx->serialise_response());
        }
      }
      catch (const std::exception& e)
      {
        // TODO: Don't pre-serialise here
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
  };

  class HTTPClientSession : public HTTPEndpoint,
                            public ccf::ClientSession,
                            public http::ResponseProcessor
  {
  private:
    http::ResponseParser response_parser;

  public:
    HTTPClientSession(
      tls::ConnID session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint(response_parser, session_id, writer_factory, std::move(ctx)),
      ClientSession(session_id, writer_factory),
      response_parser(*this)
    {}

    void send_request(http::Request&& request) override
    {
      send_request_oops(std::move(request));
    }

    void on_handshake_error(const std::string& error_msg) override
    {
      if (handle_error_cb)
      {
        handle_error_cb(error_msg);
      }
      else
      {
        LOG_FAIL_FMT("{}", error_msg);
      }
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

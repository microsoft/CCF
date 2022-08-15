// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "enclave/client_endpoint.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http_parser.h"
#include "http_rpc_context.h"

namespace http
{
  class HTTPEndpoint : public ccf::TLSEndpoint
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
      TLSEndpoint(session_id, writer_factory, std::move(ctx)),
      p(p_),
      error_reporter(error_reporter)
    {}

  public:
    static void recv_cb(std::unique_ptr<threading::Tmsg<SendRecvMsg>> msg)
    {
      reinterpret_cast<HTTPEndpoint*>(msg->data.self.get())
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

          send_raw(http::error(ccf::ErrorDetails{
            HTTP_STATUS_PAYLOAD_TOO_LARGE,
            ccf::errors::RequestBodyTooLarge,
            e.what()}));

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

          send_raw(http::error(ccf::ErrorDetails{
            HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
            ccf::errors::RequestHeaderTooLarge,
            e.what()}));

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
          send_raw(response.build_response());

          close();
          break;
        }
      }
    }
  };

  class HTTPServerEndpoint : public HTTPEndpoint, public http::RequestProcessor
  {
  private:
    http::RequestParser request_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    tls::ConnID session_id;
    ccf::ListenInterfaceID interface_id;

  public:
    HTTPServerEndpoint(
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

    void send(std::vector<uint8_t>&& data, sockaddr) override
    {
      send_raw(std::move(data));
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
          send_raw(http::error(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            e.what()));
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

  class HTTPClientEndpoint : public HTTPEndpoint,
                             public ccf::ClientEndpoint,
                             public http::ResponseProcessor
  {
  private:
    http::ResponseParser response_parser;

  public:
    HTTPClientEndpoint(
      tls::ConnID session_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<tls::Context> ctx) :
      HTTPEndpoint(response_parser, session_id, writer_factory, std::move(ctx)),
      ClientEndpoint(session_id, writer_factory),
      response_parser(*this)
    {}

    void send_request(const http::Request& request) override
    {
      send_raw(request.build_request());
    }

    void send(std::vector<uint8_t>&&, sockaddr) override
    {
      throw std::logic_error(
        "send() should not be called directly on HTTPClient");
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

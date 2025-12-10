// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_responder.h"
#include "ds/internal_logger.h"
#include "enclave/client_session.h"
#include "enclave/rpc_handler.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http_parser.h"
#include "http_rpc_context.h"

namespace http
{
  using HTTPSession = ccf::EncryptedSession;

  class HTTPServerSession : public HTTPSession,
                            public http::RequestProcessor,
                            public ccf::http::HTTPResponder
  {
  private:
    http::RequestParser request_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ccf::SessionContext> session_ctx;
    std::shared_ptr<ErrorReporter> error_reporter;
    std::shared_ptr<ccf::CommitCallbackSubsystem> commit_callbacks;
    ccf::ListenInterfaceID interface_id;

  public:
    HTTPServerSession(
      std::shared_ptr<ccf::RPCMap> rpc_map_,
      ::tcp::ConnID session_id_,
      ccf::ListenInterfaceID interface_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<ccf::tls::Context> ctx,
      const ccf::http::ParserConfiguration& configuration,
      const std::shared_ptr<ErrorReporter>& error_reporter_,
      const std::shared_ptr<ccf::CommitCallbackSubsystem>& commit_callbacks =
        nullptr) :
      HTTPSession(session_id_, writer_factory, std::move(ctx)),
      request_parser(*this, configuration),
      rpc_map(std::move(rpc_map_)),
      error_reporter(error_reporter_),
      commit_callbacks(commit_callbacks),
      interface_id(std::move(interface_id_))
    {}

    bool parse(std::span<const uint8_t> data) override
    {
      // Catch request parsing errors and convert them to error responses
      try
      {
        request_parser.execute(data.data(), data.size());

        return true;
      }
      catch (RequestPayloadTooLargeException& e)
      {
        if (error_reporter)
        {
          error_reporter->report_request_payload_too_large_error(interface_id);
        }

        LOG_DEBUG_FMT("Request is too large: {}", e.what());

        send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_PAYLOAD_TOO_LARGE,
          ccf::errors::RequestBodyTooLarge,
          e.what()});

        close_session();
      }
      catch (RequestHeaderTooLargeException& e)
      {
        if (error_reporter)
        {
          error_reporter->report_request_header_too_large_error(interface_id);
        }

        LOG_DEBUG_FMT("Request header is too large: {}", e.what());

        send_odata_error_response(ccf::ErrorDetails{
          HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
          ccf::errors::RequestHeaderTooLarge,
          e.what()});

        close_session();
      }
      catch (const std::exception& e)
      {
        if (error_reporter)
        {
          error_reporter->report_parsing_error(interface_id);
        }
        LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

        ccf::http::HeaderMap headers;
        headers[ccf::http::headers::CONTENT_TYPE] =
          ccf::http::headervalues::contenttype::TEXT;

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
          HTTP_STATUS_BAD_REQUEST,
          std::move(headers),
          {},
          std::move(response_body));

        close_session();
      }

      return false;
    }

    void handle_request(
      llhttp_method verb,
      const std::string_view& url,
      ccf::http::HeaderMap&& headers,
      std::vector<uint8_t>&& body,
      int32_t /*stream_id*/) override
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
            session_ctx,
            ccf::HttpVersion::HTTP1,
            verb,
            url,
            std::move(headers),
            std::move(body));
        }
        catch (std::exception& e)
        {
          send_odata_error_response(ccf::ErrorDetails{
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error constructing RpcContext: {}", e.what())});
          close_session();
          return;
        }

        std::shared_ptr<ccf::RpcHandler> search =
          http::fetch_rpc_handler(rpc_ctx, rpc_map);

        search->process(rpc_ctx);

        if (rpc_ctx->response_is_pending)
        {
          // If the RPC is pending, hold the connection.
          LOG_TRACE_FMT("Pending");
          return;
        }

        const auto& respond_on_commit_txid = rpc_ctx->respond_on_commit_txid;
        if (respond_on_commit_txid.has_value())
        {
          const auto tx_id = respond_on_commit_txid.value();

          // Block any future work from happening on this session, to
          // maintain session consistency
          ccf::tasks::Resumable paused_task = ccf::tasks::pause_current_task();

          // Register for a callback when this TxID is committed (or
          // invalidated)
          commit_callbacks->add_callback(
            tx_id,
            [this, rpc_ctx, paused_task](
              ccf::TxID tx_id, ccf::TxStatus status) {
              switch (status)
              {
                case ccf::TxStatus::Committed:
                {
                  // Write the response
                  this->send_response(
                    rpc_ctx->get_response_http_status(),
                    rpc_ctx->get_response_headers(),
                    rpc_ctx->get_response_trailers(),
                    std::move(rpc_ctx->take_response_body()));
                  break;
                }

                case ccf::TxStatus::Invalid:
                {
                  // If transaction is not Committed, write an error response
                  send_odata_error_response(ccf::ErrorDetails{
                    HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    ccf::errors::TransactionInvalid,
                    fmt::format(
                      "While waiting for TxID {} to commit, it was "
                      "invalidated",
                      tx_id.to_str())});
                  break;
                }

                default:
                {
                  throw std::logic_error(
                    "Unexpected TxStatus in on_commit callback");
                }
              }

              if (rpc_ctx->terminate_session)
              {
                close_session();
              }

              // Resume processing work for this session
              ccf::tasks::resume_task(paused_task);
            });
        }
        else
        {
          send_response(
            rpc_ctx->get_response_http_status(),
            rpc_ctx->get_response_headers(),
            rpc_ctx->get_response_trailers(),
            std::move(rpc_ctx->take_response_body()));

          if (rpc_ctx->terminate_session)
          {
            close_session();
          }
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
        close_session();
        throw;
      }
    }

    bool send_response(
      ccf::http_status status_code,
      ccf::http::HeaderMap&& headers,
      ccf::http::HeaderMap&& trailers,
      std::vector<uint8_t>&& body) override
    {
      if (!trailers.empty())
      {
        throw std::logic_error("Cannot return trailers over HTTP/1");
      }

      auto response = ::http::Response(status_code);
      for (const auto& [k, v] : headers)
      {
        response.set_header(k, v);
      }

      response.set_body(
        body.data(),
        body.size(),
        false /* Don't overwrite any existing content-length header */
      );

      send_data(response.build_response());
      return true;
    }
  };

  class HTTPClientSession : public HTTPSession,
                            public ccf::ClientSession,
                            public ::http::ResponseProcessor
  {
  private:
    ::http::ResponseParser response_parser;

  public:
    HTTPClientSession(
      ::tcp::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<ccf::tls::Context> ctx) :
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
        LOG_FAIL_FMT("Error parsing HTTP response on session {}", session_id);
        LOG_DEBUG_FMT("Error parsing HTTP response: {}", e.what());
        LOG_DEBUG_FMT(
          "Error occurred while parsing fragment {} byte fragment:\n{}",
          data.size(),
          std::string_view(
            reinterpret_cast<char const*>(data.data()), data.size()));

        close_session();
      }
      return false;
    }

    void send_request(http::Request&& request) override
    {
      auto data = request.build_request();
      send_data(std::move(data));
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
      ccf::http_status status,
      ccf::http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      handle_data_cb(status, std::move(headers), std::move(body));

      LOG_TRACE_FMT("Closing connection, message handled");
      close_session();
    }
  };

  using UnencryptedHTTPSession = ccf::UnencryptedSession;

  class UnencryptedHTTPClientSession : public UnencryptedHTTPSession,
                                       public ccf::ClientSession,
                                       public ::http::ResponseProcessor
  {
  private:
    ::http::ResponseParser response_parser;

  public:
    UnencryptedHTTPClientSession(
      ::tcp::ConnID session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory) :
      UnencryptedHTTPSession(session_id_, writer_factory),
      ClientSession(session_id_, writer_factory),
      response_parser(*this)
    {}

    bool parse(std::span<const uint8_t> data) override
    {
      try
      {
        response_parser.execute(data.data(), data.size());
        return true;
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Error parsing HTTP response on session {}", session_id);
        LOG_DEBUG_FMT("Error parsing HTTP response: {}", e.what());
        LOG_DEBUG_FMT(
          "Error occurred while parsing fragment {} byte fragment:\n{}",
          data.size(),
          std::string_view(
            reinterpret_cast<char const*>(data.data()), data.size()));

        close_session();
      }
      return false;
    }

    void send_request(http::Request&& request) override
    {
      auto data = request.build_request();
      send_data(std::move(data));
    }

    void connect(
      const std::string& hostname,
      const std::string& service,
      const HandleDataCallback f,
      const HandleErrorCallback e) override
    {
      ccf::ClientSession::connect(hostname, service, f, e);
    }

    void handle_response(
      ccf::http_status status,
      ccf::http::HeaderMap&& headers,
      std::vector<uint8_t>&& body) override
    {
      handle_data_cb(status, std::move(headers), std::move(body));
      LOG_TRACE_FMT("Closing connection, message handled");
      close_session();
    }
  };
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_responder.h"
#include "ds/internal_logger.h"
#include "enclave/client_session.h"
#include "enclave/rpc_map.h"
#include "error_reporter.h"
#include "http/responder_lookup.h"
#include "http2_parser.h"
#include "http_rpc_context.h"

namespace http
{
  using HTTP2Session = ccf::EncryptedSession;

  struct HTTP2SessionContext : public ccf::SessionContext
  {
    int32_t stream_id;

    HTTP2SessionContext(
      size_t client_session_id_,
      const std::vector<uint8_t>& caller_cert_,
      const std::optional<ccf::ListenInterfaceID>& interface_id_,
      http2::StreamId stream_id_) :
      ccf::SessionContext(client_session_id_, caller_cert_, interface_id_),
      stream_id(stream_id_)
    {}
  };

  class HTTP2StreamResponder : public ccf::http::HTTPResponder
  {
  private:
    http2::StreamId stream_id;

    // Associated HTTP2ServerSession may be closed while responder is held
    // elsewhere (e.g. async streaming) so keep a weak pointer to parser and
    // report an error to caller to discard responder.
    std::weak_ptr<http2::ServerParser> server_parser;

  public:
    HTTP2StreamResponder(
      http2::StreamId stream_id_,
      const std::shared_ptr<http2::ServerParser>& server_parser_) :
      stream_id(stream_id_),
      server_parser(server_parser_)
    {}

    bool send_response(
      ccf::http_status status_code,
      ccf::http::HeaderMap&& headers,
      ccf::http::HeaderMap&& trailers,
      std::vector<uint8_t>&& body) override
    {
      auto sp = server_parser.lock();
      try
      {
        sp->respond(
          stream_id,
          status_code,
          std::move(headers),
          std::move(trailers),
          std::move(body));
      }
      catch (const std::exception& e)
      {
        LOG_DEBUG_FMT(
          "Error sending response on stream {}: {}", stream_id, e.what());
        return false;
      }

      return true;
    }

    bool start_stream(
      ccf::http_status status, const ccf::http::HeaderMap& headers) override
    {
      auto sp = server_parser.lock();
      if (sp)
      {
        try
        {
          sp->start_stream(stream_id, status, headers);
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT("Error sending headers {}: {}", stream_id, e.what());
          return false;
        }
      }
      else
      {
        LOG_DEBUG_FMT("Stream {} is closed", stream_id);
        return false;
      }
      return true;
    }

    bool close_stream(ccf::http::HeaderMap&& trailers) override
    {
      auto sp = server_parser.lock();
      if (sp)
      {
        try
        {
          sp->close_stream(stream_id, std::move(trailers));
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT("Error closing stream {}: {}", stream_id, e.what());
          return false;
        }
      }
      else
      {
        LOG_DEBUG_FMT("Stream {} is closed", stream_id);
        return false;
      }
      return true;
    }

    bool stream_data(std::vector<uint8_t>&& data) override
    {
      auto sp = server_parser.lock();
      if (sp)
      {
        try
        {
          sp->send_data(stream_id, std::move(data));
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT(
            "Error streaming data on stream {}: {}", stream_id, e.what());
          return false;
        }
      }
      else
      {
        LOG_DEBUG_FMT("Stream {} is closed", stream_id);
        return false;
      }

      return true;
    }

    bool set_on_stream_close_callback(
      ccf::http::StreamOnCloseCallback cb) override
    {
      auto sp = server_parser.lock();
      if (sp)
      {
        try
        {
          sp->set_on_stream_close_callback(stream_id, cb);
        }
        catch (const std::exception& e)
        {
          LOG_DEBUG_FMT(
            "Error setting close callback on stream {}: {}",
            stream_id,
            e.what());
          return false;
        }
      }
      else
      {
        LOG_DEBUG_FMT("Stream {} is closed", stream_id);
        return false;
      }
      return true;
    }
  };

  class HTTP2ServerSession : public HTTP2Session,
                             public http::RequestProcessor,
                             public ccf::http::HTTPResponder
  {
  private:
    std::shared_ptr<http2::ServerParser> server_parser;

    std::shared_ptr<ccf::RPCMap> rpc_map;
    std::shared_ptr<ccf::RpcHandler> handler;
    std::shared_ptr<ErrorReporter> error_reporter;
    ccf::ListenInterfaceID interface_id;

    http::ResponderLookup& responder_lookup;

    std::unordered_map<http2::StreamId, std::shared_ptr<HTTP2SessionContext>>
      session_ctxs;

    std::shared_ptr<HTTP2SessionContext> get_session_ctx(
      http2::StreamId stream_id)
    {
      auto it = session_ctxs.find(stream_id);
      if (it == session_ctxs.end())
      {
        it = session_ctxs.emplace_hint(
          it,
          std::make_pair(
            stream_id,
            std::make_shared<HTTP2SessionContext>(
              session_id, tls_io->peer_cert(), interface_id, stream_id)));
      }

      return it->second;
    }

    std::shared_ptr<HTTPResponder> get_stream_responder(
      http2::StreamId stream_id)
    {
      auto responder = responder_lookup.lookup_responder(session_id, stream_id);
      if (responder == nullptr)
      {
        responder =
          std::make_shared<HTTP2StreamResponder>(stream_id, server_parser);
        responder_lookup.add_responder(session_id, stream_id, responder);
      }

      return responder;
    }

    void respond_with_error(
      http2::StreamId stream_id, const ccf::ErrorDetails& error)
    {
      nlohmann::json body = ccf::ODataErrorResponse{
        ccf::ODataError{std::move(error.code), std::move(error.msg), {}}};
      const std::string s = body.dump();
      std::vector<uint8_t> v(s.begin(), s.end());

      ccf::http::HeaderMap headers;
      headers[ccf::http::headers::CONTENT_TYPE] =
        ccf::http::headervalues::contenttype::JSON;

      get_stream_responder(stream_id)->send_response(
        error.status, std::move(headers), {}, std::move(v));
    }

  public:
    HTTP2ServerSession(
      std::shared_ptr<ccf::RPCMap> rpc_map,
      int64_t session_id_,
      const ccf::ListenInterfaceID& interface_id,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<ccf::tls::Context> ctx,
      const ccf::http::ParserConfiguration& configuration,
      const std::shared_ptr<ErrorReporter>& error_reporter,
      http::ResponderLookup& responder_lookup_) :
      HTTP2Session(session_id_, writer_factory, std::move(ctx)),
      server_parser(
        std::make_shared<http2::ServerParser>(*this, configuration)),
      rpc_map(rpc_map),
      error_reporter(error_reporter),
      interface_id(interface_id),
      responder_lookup(responder_lookup_)
    {
      server_parser->set_outgoing_data_handler(
        [this](std::span<const uint8_t> data) {
          send_data(std::vector<uint8_t>(data.begin(), data.end()));
        });
    }

    ~HTTP2ServerSession()
    {
      responder_lookup.cleanup_responders(session_id);
    }

    bool parse(std::span<const uint8_t> data) override
    {
      try
      {
        if (!server_parser->execute(data.data(), data.size()))
        {
          // Close session gracefully
          close_session();
          return false;
        }
        return true;
      }
      catch (http::RequestPayloadTooLargeException& e)
      {
        if (error_reporter)
        {
          error_reporter->report_request_payload_too_large_error(interface_id);
        }

        LOG_DEBUG_FMT("Request is too large: {}", e.what());

        auto error = ccf::ErrorDetails{
          HTTP_STATUS_PAYLOAD_TOO_LARGE,
          ccf::errors::RequestBodyTooLarge,
          e.what()};

        respond_with_error(e.get_stream_id(), error);

        close_session();
      }
      catch (http::RequestHeaderTooLargeException& e)
      {
        if (error_reporter)
        {
          error_reporter->report_request_header_too_large_error(interface_id);
        }

        LOG_DEBUG_FMT("Request header is too large: {}", e.what());

        auto error = ccf::ErrorDetails{
          HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
          ccf::errors::RequestHeaderTooLarge,
          e.what()};

        respond_with_error(e.get_stream_id(), error);

        close_session();
      }
      catch (const std::exception& e)
      {
        if (error_reporter)
        {
          error_reporter->report_parsing_error(interface_id);
        }

        LOG_DEBUG_FMT("Error parsing HTTP request: {}", e.what());

        // For generic parsing errors, as it is not trivial to construct a valid
        // HTTP/2 response to send back to the default stream (0), the session
        // is simply closed.

        close_session();
      }
      return false;
    }

    void handle_request(
      llhttp_method verb,
      const std::string_view& url,
      ccf::http::HeaderMap&& headers,
      std::vector<uint8_t>&& body,
      int32_t stream_id) override
    {
      LOG_TRACE_FMT(
        "Processing msg({}, {} [{} bytes])",
        llhttp_method_name(verb),
        url,
        body.size());

      auto responder = get_stream_responder(stream_id);
      auto session_ctx = get_session_ctx(stream_id);

      try
      {
        std::shared_ptr<http::HttpRpcContext> rpc_ctx = nullptr;
        try
        {
          rpc_ctx = std::make_shared<HttpRpcContext>(
            session_ctx,
            ccf::HttpVersion::HTTP2,
            verb,
            url,
            std::move(headers),
            std::move(body),
            responder);
        }
        catch (std::exception& e)
        {
          send_odata_error_response(ccf::ErrorDetails{
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            ccf::errors::InternalError,
            fmt::format("Error constructing RpcContext: {}", e.what())});
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
        else
        {
          responder->send_response(
            rpc_ctx->get_response_http_status(),
            rpc_ctx->get_response_headers(),
            rpc_ctx->get_response_trailers(),
            std::move(rpc_ctx->take_response_body()));
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
      return get_stream_responder(http2::DEFAULT_STREAM_ID)
        ->send_response(
          status_code,
          std::move(headers),
          std::move(trailers),
          std::move(body));
    }

    bool start_stream(
      ccf::http_status status, const ccf::http::HeaderMap& headers) override
    {
      return get_stream_responder(http2::DEFAULT_STREAM_ID)
        ->start_stream(status, headers);
    }

    bool stream_data(std::vector<uint8_t>&& data) override
    {
      return get_stream_responder(http2::DEFAULT_STREAM_ID)
        ->stream_data(std::move(data));
    }

    bool close_stream(ccf::http::HeaderMap&& trailers) override
    {
      return get_stream_responder(http2::DEFAULT_STREAM_ID)
        ->close_stream(std::move(trailers));
    }

    bool set_on_stream_close_callback(
      ccf::http::StreamOnCloseCallback cb) override
    {
      return get_stream_responder(http2::DEFAULT_STREAM_ID)
        ->set_on_stream_close_callback(cb);
    }
  };

  class HTTP2ClientSession : public HTTP2Session,
                             public ccf::ClientSession,
                             public ::http::ResponseProcessor
  {
  private:
    http2::ClientParser client_parser;

  public:
    HTTP2ClientSession(
      int64_t session_id_,
      ringbuffer::AbstractWriterFactory& writer_factory,
      std::unique_ptr<ccf::tls::Context> ctx) :
      HTTP2Session(session_id_, writer_factory, std::move(ctx)),
      ccf::ClientSession(session_id_, writer_factory),
      client_parser(*this)
    {
      client_parser.set_outgoing_data_handler(
        [this](std::span<const uint8_t> data) {
          send_data(std::vector<uint8_t>(data.begin(), data.end()));
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
          std::string_view((char const*)data.data(), data.size()));

        close_session();
      }
      return false;
    }

    void send_request(http::Request&& request) override
    {
      client_parser.send_structured_request(
        request.get_method(),
        request.get_path(),
        request.get_headers(),
        {request.get_content_data(),
         request.get_content_data() + request.get_content_length()});
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

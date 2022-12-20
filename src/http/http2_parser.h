// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"
#include "enclave/session.h"
#include "http2_callbacks.h"
#include "http2_types.h"
#include "http_proc.h"
#include "http_rpc_context.h"

namespace http2
{
  using DataHandlerCB = std::function<void(std::span<const uint8_t>)>;

  class Parser : public AbstractParser
  {
  private:
    // Keep track of last peer stream id received on this session so that we can
    // reject new streams ids less than this value.
    StreamId last_stream_id = 0;
    DataHandlerCB handle_outgoing_data;
    http::ParserConfiguration configuration;

  protected:
    std::map<StreamId, std::shared_ptr<StreamData>> streams;
    nghttp2_session* session;

  public:
    Parser(
      const http::ParserConfiguration& configuration_, bool is_client = false) :
      configuration(configuration_)
    {
      LOG_TRACE_FMT("Creating HTTP2 parser");

      nghttp2_session_callbacks* callbacks;
      nghttp2_session_callbacks_new(&callbacks);
      nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);
      nghttp2_session_callbacks_set_data_source_read_length_callback(
        callbacks, on_data_source_read_length_callback);
      nghttp2_session_callbacks_set_error_callback2(
        callbacks, on_error_callback);

      nghttp2_session_callbacks_set_on_begin_frame_callback(
        callbacks, on_begin_frame_recv_callback);
      nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks, on_frame_recv_callback);
      nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);
      nghttp2_session_callbacks_set_on_header_callback(
        callbacks, on_header_callback);
      nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, on_data_callback);

      if (is_client)
      {
        if (nghttp2_session_client_new(&session, callbacks, this) != 0)
        {
          throw std::logic_error("Could not create new HTTP/2 client session");
        }
      }
      else
      {
        if (nghttp2_session_server_new(&session, callbacks, this) != 0)
        {
          throw std::logic_error("Could not create new HTTP/2 server session");
        }
      }

      // Submit initial settings
      std::vector<nghttp2_settings_entry> settings;
      settings.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE, max_frame_size});
      // NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE is only a hint to client
      // (https://www.rfc-editor.org/rfc/rfc7540#section-10.5.1)
      settings.push_back(
        {NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
         configuration.max_headers_count.value_or(
           http::default_max_headers_count)});

      auto rv = nghttp2_submit_settings(
        session, NGHTTP2_FLAG_NONE, settings.data(), settings.size());
      if (rv != 0)
      {
        throw std::logic_error(fmt::format(
          "Error submitting settings for HTTP2 session: {}",
          nghttp2_strerror(rv)));
      }

      nghttp2_session_callbacks_del(callbacks);
    }

    virtual ~Parser()
    {
      nghttp2_session_del(session);
    }

    StreamId get_last_stream_id() const override
    {
      return last_stream_id;
    }

    http::ParserConfiguration get_configuration() const override
    {
      return configuration;
    }

    void set_outgoing_data_handler(DataHandlerCB&& cb)
    {
      handle_outgoing_data = std::move(cb);
    }

    void store_stream(
      StreamId stream_id, const std::shared_ptr<StreamData>& stream_data)
    {
      auto it = streams.find(stream_id);
      if (it != streams.end())
      {
        throw std::logic_error(fmt::format(
          "Cannot store new stream {} as it already exists", stream_id));
      }

      streams.insert(it, {stream_id, stream_data});
      last_stream_id = stream_id;
    }

    std::shared_ptr<StreamData> get_stream(StreamId stream_id) override
    {
      auto it = streams.find(stream_id);
      if (it == streams.end())
      {
        return nullptr;
      }
      return it->second;
    }

    std::shared_ptr<StreamData> create_stream(StreamId stream_id) override
    {
      auto s = std::make_shared<StreamData>();
      store_stream(stream_id, s);
      LOG_TRACE_FMT("Created new stream {}", stream_id);
      return s;
    }

    void destroy_stream(StreamId stream_id) override
    {
      auto it = streams.find(stream_id);
      if (it != streams.end())
      {
        // Erase _before_ calling close callback as `destroy_stream()` may be
        // called multiple times (once when the client closes the stream, and
        // when the server sends the final trailers)
        auto stream_data = it->second;
        it = streams.erase(it);
        LOG_TRACE_FMT("Deleted stream {}", stream_id);
        if (
          stream_data->close_callback != nullptr &&
          stream_data->outgoing.state != http2::StreamResponseState::Closing)
        {
          // Close callback is supplied by app so handle eventual exceptions
          try
          {
            stream_data->close_callback();
          }
          catch (const std::exception& e)
          {
            LOG_DEBUG_FMT("Error closing callback: {}", e.what());
          }
        }
        LOG_TRACE_FMT("Successfully destroyed stream {}", stream_id);
      }
      else
      {
        LOG_DEBUG_FMT("Cannot destroy unknown stream {}", stream_id);
      }
    }

    bool execute(const uint8_t* data, size_t size)
    {
      LOG_TRACE_FMT("http2::Parser execute: {}", size);
      auto readlen = nghttp2_session_mem_recv(session, data, size);
      if (readlen < 0)
      {
        throw std::logic_error(fmt::format(
          "HTTP/2: Error receiving data: {}", nghttp2_strerror(readlen)));
      }

      send_all_submitted();

      // Detects whether server session expects any more data to read/write, and
      // if not (e.g. goaway frame was handled), closes session gracefully
      if (
        nghttp2_session_want_read(session) == 0 &&
        nghttp2_session_want_write(session) == 0)
      {
        LOG_TRACE_FMT("http2::Parser execute: Closing session gracefully");
        return false;
      }

      return true;
    }

    void send_all_submitted()
    {
      ssize_t size = 0;
      const uint8_t* data = nullptr;
      while ((size = nghttp2_session_mem_send(session, &data)) != 0)
      {
        if (size > 0)
        {
          handle_outgoing_data({data, static_cast<size_t>(size)});
        }
        else
        {
          throw std::logic_error(fmt::format(
            "HTTP/2: Error sending data: {}", nghttp2_strerror(size)));
        }
      }
    }
  };

  class ServerParser : public Parser
  {
  private:
    http::RequestProcessor& proc;

    void submit_trailers(StreamId stream_id, http::HeaderMap&& trailers)
    {
      if (trailers.empty())
      {
        return;
      }

      LOG_TRACE_FMT("Submitting {} trailers", trailers.size());
      std::vector<nghttp2_nv> trlrs;
      trlrs.reserve(trailers.size());
      for (auto& [k, v] : trailers)
      {
        trlrs.emplace_back(make_nv(k.data(), v.data()));
      }

      int rv =
        nghttp2_submit_trailer(session, stream_id, trlrs.data(), trlrs.size());
      if (rv != 0)
      {
        throw std::logic_error(fmt::format(
          "nghttp2_submit_trailer error: {}", nghttp2_strerror(rv)));
      }
    }

    void submit_response(
      StreamId stream_id,
      http_status status,
      const http::HeaderMap& base_headers,
      const http::HeaderMap& extra_headers = {})
    {
      std::vector<nghttp2_nv> hdrs = {};

      auto status_str = fmt::format(
        "{}", static_cast<std::underlying_type<http_status>::type>(status));
      hdrs.emplace_back(make_nv(http2::headers::STATUS, status_str.data()));

      for (auto& [k, v] : base_headers)
      {
        hdrs.emplace_back(make_nv(k.data(), v.data()));
      }

      for (auto& [k, v] : extra_headers)
      {
        hdrs.emplace_back(make_nv(k.data(), v.data()));
      }

      nghttp2_data_provider prov;
      prov.read_callback = read_outgoing_callback;

      int rv = nghttp2_submit_response(
        session, stream_id, hdrs.data(), hdrs.size(), &prov);
      if (rv != 0)
      {
        throw std::logic_error(fmt::format(
          "nghttp2_submit_response error: {}", nghttp2_strerror(rv)));
      }
    }

  public:
    ServerParser(
      http::RequestProcessor& proc_,
      const http::ParserConfiguration& configuration_) :
      Parser(configuration_, false),
      proc(proc_)
    {}

    void set_on_stream_close_callback(StreamId stream_id, StreamCloseCB cb)
    {
      LOG_TRACE_FMT(
        "http2::set_on_stream_close_callback: stream {}", stream_id);

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        throw std::logic_error(
          fmt::format("Stream {} no longer exists", stream_id));
      }

      stream_data->close_callback = cb;
    }

    void respond(
      StreamId stream_id,
      http_status status,
      const http::HeaderMap& headers,
      http::HeaderMap&& trailers,
      std::span<const uint8_t> body)
    {
      LOG_TRACE_FMT(
        "http2::respond: stream {} - {} headers - {} trailers - {} bytes "
        "body",
        stream_id,
        headers.size(),
        trailers.size(),
        body.size());

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        throw std::logic_error(
          fmt::format("Stream {} no longer exists", stream_id));
      }

      bool should_submit_response =
        stream_data->outgoing.state != StreamResponseState::Streaming;

      stream_data->outgoing.state = StreamResponseState::Closing;

      http::HeaderMap extra_headers = {};
      extra_headers[http::headers::CONTENT_LENGTH] =
        std::to_string(body.size());
      auto thv = make_trailer_header_value(trailers);
      if (thv.has_value())
      {
        extra_headers[http::headers::TRAILER] = thv.value();
      }

      stream_data->outgoing.body = DataSource(body);
      stream_data->outgoing.has_trailers = !trailers.empty();

      if (should_submit_response)
      {
        submit_response(stream_id, status, headers, extra_headers);
        send_all_submitted();
      }

      submit_trailers(stream_id, std::move(trailers));
      send_all_submitted();
    }

    void start_stream(
      StreamId stream_id, http_status status, const http::HeaderMap& headers)
    {
      LOG_TRACE_FMT(
        "http2::start_stream: stream {} - {} headers",
        stream_id,
        headers.size());

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        throw std::logic_error(
          fmt::format("Stream {} no longer exists", stream_id));
      }

      if (stream_data->outgoing.state != StreamResponseState::Uninitialised)
      {
        throw std::logic_error(fmt::format(
          "Stream {} should be uninitialised to start stream", stream_id));
      }

      stream_data->outgoing.state = StreamResponseState::Streaming;

      submit_response(stream_id, status, headers);
      send_all_submitted();
    }

    void send_data(StreamId stream_id, std::span<const uint8_t> data)
    {
      LOG_TRACE_FMT(
        "http2::send_data: stream {} - {} bytes", stream_id, data.size());

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        throw std::logic_error(
          fmt::format("Stream {} no longer exists", stream_id));
      }

      if (stream_data->outgoing.state != StreamResponseState::Streaming)
      {
        throw std::logic_error(
          fmt::format("Stream {} should be streaming to send data", stream_id));
      }

      stream_data->outgoing.body = DataSource(data);

      int rv = nghttp2_session_resume_data(session, stream_id);
      if (rv < 0)
      {
        throw std::logic_error(fmt::format(
          "nghttp2_session_resume_data error: {}", nghttp2_strerror(rv)));
      }

      send_all_submitted();
    }

    void close_stream(StreamId stream_id, http::HeaderMap&& trailers)
    {
      LOG_TRACE_FMT(
        "http2::close: stream {} - {} trailers ", stream_id, trailers.size());

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        throw std::logic_error(
          fmt::format("Stream {} no longer exists", stream_id));
      }

      auto it = streams.find(stream_id);
      if (it != streams.end())
      {
        stream_data->outgoing.state = StreamResponseState::Closing;
        stream_data->outgoing.has_trailers = !trailers.empty();

        submit_trailers(stream_id, std::move(trailers));
        send_all_submitted();
      }
      // else this stream was already closed by client, and we shouldn't send
      // trailers
    }

    virtual void handle_completed(
      StreamId stream_id, StreamData* stream_data) override
    {
      LOG_TRACE_FMT("http2::ServerParser: handle_completed");

      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("No stream data to handle request");
        return;
      }

      auto& headers = stream_data->incoming.headers;

      std::string url = {};
      {
        const auto url_it = headers.find(http2::headers::PATH);
        if (url_it != headers.end())
        {
          url = url_it->second;
        }
      }

      llhttp_method method = {};
      {
        const auto method_it = headers.find(http2::headers::METHOD);
        if (method_it != headers.end())
        {
          method = ccf::http_method_from_str(method_it->second.c_str());
        }
      }

      proc.handle_request(
        method,
        url,
        std::move(stream_data->incoming.headers),
        std::move(stream_data->incoming.body),
        stream_id);
    }
  };

  class ClientParser : public Parser
  {
  private:
    http::ResponseProcessor& proc;

  public:
    ClientParser(http::ResponseProcessor& proc_) :
      Parser(http::ParserConfiguration{}, true),
      proc(proc_)
    {}

    void send_structured_request(
      llhttp_method method,
      const std::string& route,
      const http::HeaderMap& headers,
      std::span<const uint8_t> body)
    {
      std::vector<nghttp2_nv> hdrs;
      hdrs.emplace_back(
        make_nv(http2::headers::METHOD, llhttp_method_name(method)));
      hdrs.emplace_back(make_nv(http2::headers::PATH, route.data()));
      hdrs.emplace_back(make_nv(":scheme", "https"));
      hdrs.emplace_back(make_nv(":authority", "localhost:8080"));
      for (auto const& [k, v] : headers)
      {
        hdrs.emplace_back(make_nv(k.data(), v.data()));
      }

      auto stream_data = std::make_shared<StreamData>();
      stream_data->outgoing.body = DataSource(body);

      nghttp2_data_provider prov;
      prov.read_callback = read_outgoing_callback;

      stream_data->outgoing.state = StreamResponseState::Closing;

      auto stream_id = nghttp2_submit_request(
        session, nullptr, hdrs.data(), hdrs.size(), &prov, stream_data.get());
      if (stream_id < 0)
      {
        LOG_FAIL_FMT(
          "Could not submit HTTP request: {}", nghttp2_strerror(stream_id));
        return;
      }

      store_stream(stream_id, stream_data);

      send_all_submitted();
      LOG_DEBUG_FMT("Successfully sent request with stream id: {}", stream_id);
    }

    void handle_completed(StreamId stream_id, StreamData* stream_data) override
    {
      LOG_TRACE_FMT("http2::ClientParser: handle_completed");

      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("No stream data to handle response");
        return;
      }

      auto& headers = stream_data->incoming.headers;

      http_status status = {};
      {
        const auto status_it = headers.find(http2::headers::STATUS);
        if (status_it != headers.end())
        {
          status = http_status(std::stoi(status_it->second));
        }
      }

      proc.handle_response(
        status,
        std::move(stream_data->incoming.headers),
        std::move(stream_data->incoming.body));
    }
  };
}

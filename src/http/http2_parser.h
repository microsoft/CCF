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
  protected:
    nghttp2_session* session;
    std::map<StreamId, std::shared_ptr<StreamData>> streams;
    DataHandlerCB handle_outgoing_data;

  public:
    Parser(bool is_client = false)
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
      settings.push_back({NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1});
      settings.push_back({NGHTTP2_SETTINGS_MAX_FRAME_SIZE, max_data_read_size});

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

    void set_outgoing_data_handler(DataHandlerCB&& cb)
    {
      handle_outgoing_data = std::move(cb);
    }

    std::shared_ptr<StreamData> create_stream(StreamId stream_id) override
    {
      auto stream_data = std::make_shared<StreamData>();
      store_stream(stream_id, stream_data);
      return stream_data;
    }

    void destroy_stream(StreamId stream_id) override
    {
      auto it = streams.find(stream_id);
      if (it != streams.end())
      {
        it = streams.erase(it);
        LOG_TRACE_FMT("Successfully destroyed stream {}", stream_id);
      }
      else
      {
        LOG_FAIL_FMT("Cannot destroy unknown stream {}", stream_id);
      }
    }

    void store_stream(
      StreamId stream_id, const std::shared_ptr<StreamData>& stream_data)
    {
      auto it = streams.find(stream_id);
      if (it == streams.end())
      {
        streams.insert(it, {stream_id, stream_data});
        LOG_TRACE_FMT("Successfully stored stream {}", stream_id);
      }
      else
      {
        it->second = stream_data;
        LOG_FAIL_FMT("Overwriting stored stream {}!!", stream_id);
      }
    }

    void execute(const uint8_t* data, size_t size)
    {
      LOG_TRACE_FMT("http2::Parser execute: {}", size);
      auto readlen = nghttp2_session_mem_recv(session, data, size);
      if (readlen < 0)
      {
        throw std::logic_error(fmt::format(
          "HTTP/2: Error receiving data: {}", nghttp2_strerror(readlen)));
      }

      send_all_submitted();
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

  public:
    ServerParser(http::RequestProcessor& proc_) : Parser(false), proc(proc_) {}

    void respond(
      StreamId stream_id,
      http_status status,
      const http::HeaderMap& headers,
      http::HeaderMap&& trailers,
      std::vector<uint8_t>&& body)
    {
      LOG_TRACE_FMT(
        "http2::respond: stream {} - {} headers - {} trailers - {} bytes "
        "body",
        stream_id,
        headers.size(),
        trailers.size(),
        body.size());

      std::vector<nghttp2_nv> hdrs;
      auto status_str = fmt::format(
        "{}", static_cast<std::underlying_type<http_status>::type>(status));
      hdrs.emplace_back(make_nv(http2::headers::STATUS, status_str.data()));
      std::string body_size = std::to_string(body.size());
      hdrs.emplace_back(
        make_nv(http::headers::CONTENT_LENGTH, body_size.data()));

      using HeaderKeysIt = nonstd::KeyIterator<http::HeaderMap::iterator>;
      const auto trailer_header_val = fmt::format(
        "{}",
        fmt::join(
          HeaderKeysIt(trailers.begin()), HeaderKeysIt(trailers.end()), ","));

      if (!trailer_header_val.empty())
      {
        hdrs.emplace_back(
          make_nv(http::headers::TRAILER, trailer_header_val.c_str()));
      }

      for (auto& [k, v] : headers)
      {
        hdrs.emplace_back(make_nv(k.data(), v.data()));
      }

      auto* stream_data = get_stream_data(session, stream_id);
      stream_data->response_body = StreamData::ResponseBody(std::move(body));
      stream_data->trailers = std::move(trailers);

      nghttp2_data_provider prov;
      prov.read_callback = read_body_callback;

      int rv = nghttp2_submit_response(
        session, stream_id, hdrs.data(), hdrs.size(), &prov);
      if (rv != 0)
      {
        throw std::logic_error(
          fmt::format("nghttp2_submit_response error: {}", rv));
      }

      send_all_submitted();
    }

    void set_no_unary(StreamId stream_id)
    {
      // TODO: Can this be removed altogether?
      LOG_TRACE_FMT("http2::set_no_unary: stream {}", stream_id);

      auto* stream_data = get_stream_data(session, stream_id);
      stream_data->response_state = StreamResponseState::AboutToStream;
    }

    void send_data(
      StreamId stream_id, std::vector<uint8_t>&& data, bool close = false)
    {
      LOG_TRACE_FMT(
        "http2::send_data: stream {} - {} bytes (close: {})",
        stream_id,
        data.size(),
        close);

      auto* stream_data = get_stream_data(session, stream_id);

      stream_data->response_body = StreamData::ResponseBody(std::move(data));
      if (close)
      {
        stream_data->response_state = StreamResponseState::Closing;
      }

      int rv = nghttp2_session_resume_data(session, stream_id);
      if (rv < 0)
      {
        throw std::logic_error(fmt::format(
          "nghttp2_session_resume_data error: {}", nghttp2_strerror(rv)));
      }

      send_all_submitted();
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

      auto& headers = stream_data->headers;

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
        std::move(stream_data->headers),
        std::move(stream_data->request_body),
        stream_id);
    }
  };

  class ClientParser : public Parser
  {
  private:
    http::ResponseProcessor& proc;

  public:
    ClientParser(http::ResponseProcessor& proc_) : Parser(true), proc(proc_) {}

    void send_structured_request(
      llhttp_method method,
      const std::string& route,
      const http::HeaderMap& headers,
      std::vector<uint8_t>&& body)
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

      LOG_INFO_FMT(
        "Trying submit_request with user_data set to {}", (size_t)&body);

      nghttp2_data_provider prov;
      prov.read_callback = read_body_callback;

      auto stream_id = nghttp2_submit_request(
        session, nullptr, hdrs.data(), hdrs.size(), &prov, nullptr);
      if (stream_id < 0)
      {
        LOG_FAIL_FMT(
          "Could not submit HTTP request: {}", nghttp2_strerror(stream_id));
        return;
      }

      auto stream_data = create_stream(stream_id);
      stream_data->response_body = std::move(body);

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

      auto& headers = stream_data->headers;

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
        std::move(stream_data->headers),
        std::move(stream_data->request_body));
    }
  };
}

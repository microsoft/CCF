// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"
#include "enclave/endpoint.h"
#include "http2_types.h"
#include "http_proc.h"
#include "http_rpc_context.h"

namespace http2
{
  static ssize_t send_callback(
    nghttp2_session* session,
    const uint8_t* data,
    size_t length,
    int flags,
    void* user_data)
  {
    LOG_TRACE_FMT("http2::send_callback: {}", length);

    auto* s = get_session(user_data);
    s->send(data, length);
    return length;
  }

  static ssize_t read_callback(
    nghttp2_session* session,
    StreamId stream_id,
    uint8_t* buf,
    size_t length,
    uint32_t* data_flags,
    nghttp2_data_source* source,
    void* user_data)
  {
    auto* stream_data = get_stream_data(session, stream_id);
    auto& response_body = stream_data->response_body;
    size_t to_read =
      std::min(response_body.size() - stream_data->current_offset, length);
    LOG_TRACE_FMT("http2::read_callback: {}", to_read);

    LOG_FAIL_FMT("stream_data->state: {}", (int)stream_data->state);

    LOG_FAIL_FMT("to read: {}", to_read);

    if (to_read == 0 && stream_data->state == StreamState::Streaming)
    {
      // Note: avoid infinite loop when this function is called when server is
      // streaming (TODO: why?)
      return NGHTTP2_ERR_DEFERRED;
    }

    if (to_read > 0)
    {
      // Note: Explore zero-copy alternative (NGHTTP2_DATA_FLAG_NO_COPY)
      LOG_FAIL_FMT("Copy {} bytes", to_read);
      memcpy(buf, response_body.data() + stream_data->current_offset, to_read);
      stream_data->current_offset += to_read;
    }

    if (stream_data->current_offset >= response_body.size())
    {
      if (stream_data->state == StreamState::Closing)
      {
        LOG_FAIL_FMT("Setting flag eof");
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      }
      stream_data->current_offset = 0;
      response_body.clear();
    }

    if (
      stream_data->state == StreamState::Closing &&
      !stream_data->trailers.empty())
    {
      LOG_TRACE_FMT("Submitting {} trailers", stream_data->trailers.size());
      std::vector<nghttp2_nv> trlrs;
      trlrs.reserve(stream_data->trailers.size());
      for (auto& [k, v] : stream_data->trailers)
      {
        trlrs.emplace_back(make_nv(k.data(), v.data()));
      }

      int rv =
        nghttp2_submit_trailer(session, stream_id, trlrs.data(), trlrs.size());
      if (rv != 0)
      {
        throw std::logic_error(
          fmt::format("nghttp2_submit_trailer error: {}", rv));
      }
      else
      {
        if (stream_data->state == StreamState::Closing)
        {
          LOG_FAIL_FMT("Setting flag end stream");
          *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        }
      }
    }

    if (stream_data->state == StreamState::AboutToStream)
    {
      LOG_FAIL_FMT("Deferring data");
      stream_data->state = StreamState::Streaming;
      return NGHTTP2_ERR_DEFERRED;
    }

    LOG_FAIL_FMT("Copied {} bytes", to_read);
    return to_read;
  }

  static ssize_t read_callback_client(
    nghttp2_session* session,
    StreamId stream_id,
    uint8_t* buf,
    size_t length,
    uint32_t* data_flags,
    nghttp2_data_source* source,
    void* user_data)
  {
    LOG_TRACE_FMT("http2::read_callback client: {}", length);

    auto* stream_data = get_stream_data(session, stream_id);

    auto& request_body = stream_data->request_body;

    // Note: Explore zero-copy alternative (NGHTTP2_DATA_FLAG_NO_COPY)
    size_t to_read =
      std::min(request_body.size() - stream_data->current_offset, length);
    LOG_TRACE_FMT(
      "Request body size: {}, offset: {}, to_read: {}",
      request_body.size(),
      stream_data->current_offset,
      to_read);
    if (request_body.size() > 0)
    {
      memcpy(buf, request_body.data() + stream_data->current_offset, to_read);
      stream_data->current_offset += to_read;
    }
    if (stream_data->current_offset >= request_body.size())
    {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      stream_data->current_offset = 0;
      request_body.clear();
    }
    return to_read;
  }

  static int on_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("http2::on_frame_recv_callback, type: {}", frame->hd.type);

    auto* s = get_session(user_data);
    auto* stream_data = get_stream_data(session, frame->hd.stream_id);

    switch (frame->hd.type)
    {
      case NGHTTP2_DATA:
      case NGHTTP2_HEADERS:
      {
        LOG_TRACE_FMT("Headers/Data frame");
        // For DATA and HEADERS frame, this callback may be called after
        // on_stream_close_callback so check that stream_data still alive.
        if (stream_data == nullptr)
        {
          LOG_FAIL_FMT("No stream_data");
          return 0;
        }

        // If the request is complete, process it
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
          s->handle_request(stream_data);
        }
        break;
      }
      default:
      {
        break;
      }
    }

    return 0;
  }

  static int on_frame_recv_callback_client(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT(
      "http2::on_frame_recv_callback_client, type: {}", frame->hd.type);

    auto* s = get_session(user_data);
    auto* stream_data = get_stream_data(session, frame->hd.stream_id);

    switch (frame->hd.type)
    {
      case NGHTTP2_DATA:
      {
        LOG_TRACE_FMT("Data frame: {}", frame->headers.cat);
        if (stream_data->id == frame->hd.stream_id)
        {
          LOG_DEBUG_FMT("All headers received");
          s->handle_response(stream_data);
        }
        break;
      }
      default:
      {
        break;
      }
    }
    return 0;
  }

  static int on_begin_headers_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("http2::on_begin_headers_callback");

    auto* s = get_session(user_data);
    auto stream_data = std::make_shared<StreamData>(frame->hd.stream_id);
    s->add_stream(stream_data);
    auto rc = nghttp2_session_set_stream_user_data(
      session, frame->hd.stream_id, stream_data.get());
    if (rc != 0)
    {
      throw std::logic_error(fmt::format(
        "HTTP/2: Could not set user data for stream {}: {}",
        frame->hd.stream_id,
        nghttp2_strerror(rc)));
    }

    return 0;
  }

  static int on_begin_headers_callback_client(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT(
      "http2::on_begin_headers_callback_client: {}", frame->hd.type);

    return 0;
  }

  static int on_header_callback(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name,
    size_t namelen,
    const uint8_t* value,
    size_t valuelen,
    uint8_t flags,
    void* user_data)
  {
    auto k = std::string(name, name + namelen);
    auto v = std::string(value, value + valuelen);
    LOG_TRACE_FMT("http2::on_header_callback: {}:{}", k, v);

    auto* s = get_session(user_data);
    auto* stream_data = get_stream_data(session, frame->hd.stream_id);

    if (k == http2::headers::PATH)
    {
      stream_data->url = v;
    }
    else if (k == http2::headers::METHOD)
    {
      stream_data->verb = v;
    }
    else
    {
      stream_data->headers.emplace(k, v);
    }

    return 0;
  }

  static int on_header_callback_client(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name,
    size_t namelen,
    const uint8_t* value,
    size_t valuelen,
    uint8_t flags,
    void* user_data)
  {
    auto k = std::string(name, name + namelen);
    auto v = std::string(value, value + valuelen);
    LOG_TRACE_FMT("http2::on_header_callback_client: {}:{}", k, v);

    auto* stream_data = get_stream_data(session, frame->hd.stream_id);

    if (k == http2::headers::STATUS)
    {
      stream_data->status = http_status(std::stoi(v));
    }
    else
    {
      stream_data->headers.emplace(k, v);
    }

    return 0;
  }

  static int on_data_callback(
    nghttp2_session* session,
    uint8_t flags,
    StreamId stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data)
  {
    LOG_TRACE_FMT("http2::on_data_callback: {}", stream_id);

    auto* stream_data = get_stream_data(session, stream_id);

    stream_data->request_body.insert(
      stream_data->request_body.end(), data, data + len);

    return 0;
  }

  static int on_data_callback_client(
    nghttp2_session* session,
    uint8_t flags,
    StreamId stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data)
  {
    LOG_TRACE_FMT("http2::on_data_callback_client: {}", stream_id);

    auto* stream_data = get_stream_data(session, stream_id);

    stream_data->response_body.insert(
      stream_data->response_body.end(), data, data + len);

    return 0;
  }

  static int on_stream_close_callback(
    nghttp2_session* session,
    StreamId stream_id,
    uint32_t error_code,
    void* user_data)
  {
    LOG_TRACE_FMT(
      "http2::on_stream_close_callback: {}, {}", stream_id, error_code);

    // Note: Stream should be closed correctly here

    return 0;
  }

  static ssize_t on_data_source_read_length_callback(
    nghttp2_session* session,
    uint8_t frame_type,
    int32_t stream_id,
    int32_t session_remote_window_size,
    int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size,
    void* user_data)
  {
    LOG_TRACE_FMT(
      "http2::on_data_source_read_length_callback: {}, {}, allowed [1, "
      "min({},{},{})]",
      stream_id,
      max_data_read_size,
      session_remote_window_size,
      stream_remote_window_size,
      remote_max_frame_size);

    return max_data_read_size;
  }

  static int on_error_callback(
    nghttp2_session* session,
    int lib_error_code,
    const char* msg,
    size_t len,
    void* user_data)
  {
    LOG_FAIL_FMT("HTTP/2 error: {}", std::string(msg, msg + len));
    return 0;
  }

  class Session : public AbstractSession
  {
  protected:
    nghttp2_session* session;
    std::list<std::shared_ptr<StreamData>> streams;
    ccf::Endpoint& endpoint;

  public:
    Session(ccf::Endpoint& endpoint, bool is_client = false) :
      endpoint(endpoint)
    {
      LOG_TRACE_FMT("Created HTTP2 session");
      nghttp2_session_callbacks* callbacks;
      nghttp2_session_callbacks_new(&callbacks);
      nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
      nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);
      nghttp2_session_callbacks_set_data_source_read_length_callback(
        callbacks, on_data_source_read_length_callback);
      nghttp2_session_callbacks_set_error_callback2(
        callbacks, on_error_callback);

      if (is_client)
      {
        nghttp2_session_callbacks_set_on_frame_recv_callback(
          callbacks, on_frame_recv_callback_client);
        nghttp2_session_callbacks_set_on_begin_headers_callback(
          callbacks, on_begin_headers_callback_client);
        nghttp2_session_callbacks_set_on_header_callback(
          callbacks, on_header_callback_client);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
          callbacks, on_data_callback_client);
        nghttp2_session_client_new(&session, callbacks, this);
      }
      else
      {
        nghttp2_session_callbacks_set_on_frame_recv_callback(
          callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_begin_headers_callback(
          callbacks, on_begin_headers_callback);
        nghttp2_session_callbacks_set_on_header_callback(
          callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
          callbacks, on_data_callback);

        if (nghttp2_session_server_new(&session, callbacks, this) != 0)
        {
          throw std::logic_error("Could not create new HTTP/2 server session");
        }
      }

      nghttp2_session_callbacks_del(callbacks);
    }

    virtual ~Session()
    {
      nghttp2_session_del(session);
    }

    void add_stream(const std::shared_ptr<StreamData>& stream_data) override
    {
      streams.push_back(stream_data);
    }

    void send(const uint8_t* data, size_t length) override
    {
      LOG_TRACE_FMT("http2::Session send: {}", length);

      // Note: Remove extra copy
      std::vector<uint8_t> resp = {data, data + length};
      endpoint.send(std::move(resp), sockaddr());
    }

    void recv(const uint8_t* data, size_t size)
    {
      LOG_TRACE_FMT("http2::Session recv: {}", size);
      auto readlen = nghttp2_session_mem_recv(session, data, size);
      if (readlen < 0)
      {
        throw std::logic_error(fmt::format(
          "HTTP/2: Error receiving data: {}", nghttp2_strerror(readlen)));
      }

      auto rc = nghttp2_session_send(session);
      if (rc < 0)
      {
        throw std::logic_error(
          fmt::format("nghttp2_session_send: {}", nghttp2_strerror(rc)));
      }
    }
  };

  class ServerSession : public Session
  {
  private:
    http::RequestProcessor& proc;

  public:
    ServerSession(http::RequestProcessor& proc_, ccf::Endpoint& endpoint_) :
      Session(endpoint_, false),
      proc(proc_)
    {
      LOG_TRACE_FMT("Initialising HTTP2 Server Session");

      // Note: Should be set by operator on node startup
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
    }

    void set_no_unary(StreamId stream_id)
    {
      LOG_TRACE_FMT("http2::set_no_unary: stream {}", stream_id);

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("stream not found!");
        return;
      }

      stream_data->state = StreamState::AboutToStream;
      LOG_FAIL_FMT("No longer unary!");
    }

    void send_data(StreamId stream_id, std::vector<uint8_t>&& data, bool close)
    {
      LOG_TRACE_FMT("http2::send_data: stream {} - {}", stream_id, data.size());

      auto* stream_data = get_stream_data(session, stream_id);
      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("stream not found!");
        return;
      }

      stream_data->response_body = std::move(data);
      if (close)
      {
        stream_data->state = StreamState::Closing;
      }

      // nghttp2_data_provider prov;
      // prov.read_callback = read_callback;

      // TODO: Look at test_nghttp2_session_defer_data in nghttp2 repo for
      // unit test. It seems that it is the right way to do this.

      // if (stream_data->state == StreamState::Streaming)
      // {
      int rv = nghttp2_session_resume_data(session, stream_id);
      LOG_FAIL_FMT("resume data: {}", rv);
      if (rv < 0)
      {
        throw std::logic_error(fmt::format(
          "nghttp2_session_resume_data error: {}", nghttp2_strerror(rv)));
      }
      // }

      auto rc = nghttp2_session_send(session);
      if (rc < 0)
      {
        throw std::logic_error(
          fmt::format("nghttp2_session_send: {}", nghttp2_strerror(rc)));
      }
    }

    void send_response(
      StreamId stream_id,
      http_status status,
      const http::HeaderMap& headers,
      http::HeaderMap&& trailers,
      std::vector<uint8_t>&& body)
    {
      LOG_TRACE_FMT(
        "http2::send_response: stream {} - {} - {} - {}",
        stream_id,
        headers.size(),
        body.size(),
        trailers.size());

      std::string body_size = std::to_string(body.size());
      std::vector<nghttp2_nv> hdrs;
      auto status_str = fmt::format(
        "{}", static_cast<std::underlying_type<http_status>::type>(status));
      hdrs.emplace_back(make_nv(http2::headers::STATUS, status_str.data()));
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
      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("stream not found!");
        return;
      }
      stream_data->response_body = std::move(body);

      stream_data->trailers = std::move(trailers);

      // Note: response body is currently stored in StreamData, accessible from
      // read_callback
      nghttp2_data_provider prov;
      prov.read_callback = read_callback;

      int rv = nghttp2_submit_response(
        session, stream_id, hdrs.data(), hdrs.size(), &prov);
      if (rv != 0)
      {
        throw std::logic_error(fmt::format(
          "nghttp2_submit_response error: {}", nghttp2_strerror(rv)));
      }
    }

    virtual void handle_request(StreamData* stream_data) override
    {
      LOG_TRACE_FMT("http2::ServerSession: handle_request");

      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("No stream data to handle request");
        return;
      }

      proc.handle_request(
        stream_data->verb.get_http_method().value(),
        stream_data->url,
        std::move(stream_data->headers),
        std::move(stream_data->request_body),
        stream_data->id);
    }

    void handle_response(StreamData* stream_data) override
    {
      // Server does not handle responses
      return;
    }
  };

  class ClientSession : public Session
  {
  private:
    http::ResponseProcessor& proc;

  public:
    ClientSession(http::ResponseProcessor& proc_, ccf::Endpoint& endpoint_) :
      Session(endpoint_, true),
      proc(proc_)
    {
      LOG_TRACE_FMT("Initialising HTTP2 Client Session");
    }

    void send_structured_request(
      llhttp_method method,
      const std::string& route,
      const http::HeaderMap& headers,
      std::vector<uint8_t>&& body)
    {
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

      auto stream_data = std::make_shared<StreamData>(0);

      stream_data->request_body = std::move(body);

      // Note: response body is currently stored in StreamData, accessible from
      // read_callback
      nghttp2_data_provider prov;
      prov.read_callback = read_callback_client;

      auto stream_id = nghttp2_submit_request(
        session, nullptr, hdrs.data(), hdrs.size(), &prov, stream_data.get());
      if (stream_id < 0)
      {
        LOG_FAIL_FMT(
          "Could not submit HTTP request: {}", nghttp2_strerror(stream_id));
        return;
      }

      stream_data->id = stream_id;

      auto rc = nghttp2_session_send(session);
      if (rc < 0)
      {
        LOG_FAIL_FMT("http2:nghttp2_session_send: {}", nghttp2_strerror(rc));
        return;
      }

      add_stream(stream_data);
      LOG_DEBUG_FMT("Successfully sent request with stream id: {}", stream_id);
    }

    virtual void handle_request(StreamData* stream_data) override
    {
      // Client does not handle requests
      return;
    }

    void handle_response(StreamData* stream_data) override
    {
      proc.handle_response(
        stream_data->status,
        std::move(stream_data->headers),
        std::move(stream_data->response_body));
    }
  };
}

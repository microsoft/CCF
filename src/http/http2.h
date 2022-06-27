// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/endpoint.h" // TODO: Not great!
#include "http_builder.h"
#include "http_proc.h"
#include "http_rpc_context.h"

#include <list>
#include <memory>
#include <nghttp2/nghttp2.h>

// TODO: State of things as of 30/05/22:
//
// Next: Cleanup and forwarding.
//
// - HTTP works up to service opening (and a little more)
// - Join protocol working
// - Overall flow is sound and most callback are correctly set
// - What isn't clear is how http2::Session fits with HTTPEndpoint.
// - Forwarding is really awkward because the primary node needs to calls into
// nghttp2_submit_response() to send the response back to the backup. So the
// endpoint created on the primary when a request is forwarded needs to have
// special nghttp2 send callbacks to send back to the n2n channel. This also
// implies that the n2n channel needs to be an HTTP/2 session, which is a lot of
// work.
// - A larger refactoring is required as HTTP/1 is easy enough that
// ctx->serialised_response() is called very early on (frontend.h), but we
// cannot serialise the response early with HTTP/2 (as response headers and body
// are passed separately). Also, http2.h needs to be able to write to the
// endpoint directly, whereas http_parser only consumes input data but never
// writes to ring buffer. Note that it's probably wise to implement join
// protocol before doing this refactoring.

namespace http2
{
  using StreamId = int32_t;

  // TODO: Make configurable
  constexpr static size_t max_data_read_size = 2 << 20;

  static ssize_t send_callback(
    nghttp2_session* session,
    const uint8_t* data,
    size_t length,
    int flags,
    void* user_data);
  static int on_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_frame_recv_callback_client(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_begin_headers_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_begin_headers_callback_client(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_header_callback(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name,
    size_t namelen,
    const uint8_t* value,
    size_t valuelen,
    uint8_t flags,
    void* user_data);
  static int on_header_callback_client(
    nghttp2_session* session,
    const nghttp2_frame* frame,
    const uint8_t* name,
    size_t namelen,
    const uint8_t* value,
    size_t valuelen,
    uint8_t flags,
    void* user_data);
  static int on_data_callback(
    nghttp2_session* session,
    uint8_t flags,
    StreamId stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data);
  static int on_data_callback_client(
    nghttp2_session* session,
    uint8_t flags,
    StreamId stream_id,
    const uint8_t* data,
    size_t len,
    void* user_data);
  static int on_stream_close_callback(
    nghttp2_session* session,
    StreamId stream_id,
    uint32_t error_code,
    void* user_data);
  static ssize_t on_data_source_read_length_callback(
    nghttp2_session* session,
    uint8_t frame_type,
    int32_t stream_id,
    int32_t session_remote_window_size,
    int32_t stream_remote_window_size,
    uint32_t remote_max_frame_size,
    void* user_data);
  static int on_error_callback(
    nghttp2_session* session,
    int lib_error_code,
    const char* msg,
    size_t len,
    void* user_data);

  static nghttp2_nv make_nv(const uint8_t* key, const uint8_t* value)
  {
    // TODO: Investigate no copy flags here
    return {
      const_cast<uint8_t*>(key),
      const_cast<uint8_t*>(value),
      strlen((char*)key),
      strlen((char*)value),
      NGHTTP2_NV_FLAG_NONE};
  }

  static nghttp2_nv make_nv(const char* key, const char* value)
  {
    return make_nv((uint8_t*)key, (uint8_t*)value);
  }

  struct StreamData
  {
    StreamId id;
    http::HeaderMap headers;
    std::string url;
    ccf::RESTVerb verb;
    std::vector<uint8_t> request_body;
    http_status status;

    // Response
    std::vector<uint8_t> response_body;

    StreamData(StreamId id_) : id(id_) {}
  };

  class Session
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

        nghttp2_session_server_new(&session, callbacks, this);
      }

      nghttp2_session_callbacks_del(callbacks);
    }

    void add_stream(const std::shared_ptr<StreamData>& stream_data)
    {
      streams.push_back(stream_data);
    }

    void send(const uint8_t* data, size_t length)
    {
      LOG_TRACE_FMT("http2::Session send: {}", length);

      std::vector<uint8_t> resp = {
        data, data + length}; // TODO: Remove extra copy
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

    virtual void handle_request(StreamData* stream_data) = 0;
    virtual void handle_response(StreamData* stream_data) = 0;
  };

  static ssize_t send_callback(
    nghttp2_session* session,
    const uint8_t* data,
    size_t length,
    int flags,
    void* user_data)
  {
    LOG_TRACE_FMT("send_callback: {}", length);

    auto* s = reinterpret_cast<Session*>(user_data);
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
    LOG_TRACE_FMT("read_callback: {}", length);

    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));

    auto& response_body = stream_data->response_body;

    LOG_FAIL_FMT("Response body of size: {}", response_body.size());

    if (response_body.size() > 0)
    {
      // TODO: Explore zero-copy alternative
      memcpy(buf, response_body.data(), response_body.size());
    }

    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    // *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;

    return response_body.size();
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
    LOG_TRACE_FMT("read_callback client: {}", length);

    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));

    auto& request_body = stream_data->request_body;
    LOG_FAIL_FMT("Request body size: {}", request_body.size());

    // TODO: Explore zero-copy alternative
    // TODO: Also bump maximum size for SGX enclave and join protocol
    // https://nghttp2.org/documentation/types.html#c.nghttp2_data_source_read_length_callback
    memcpy(buf, request_body.data(), request_body.size());
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return request_body.size();
  }

  static int on_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("on_frame_recv_callback, type: {}", frame->hd.type);

    auto* s = reinterpret_cast<Session*>(user_data);
    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

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
        // TODO: Support other frame types
        break;
      }
    }

    return 0;
  }

  static int on_frame_recv_callback_client(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("on_frame_recv_callback_client, type: {}", frame->hd.type);

    auto* s = reinterpret_cast<Session*>(user_data);
    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

    switch (frame->hd.type)
    {
      case NGHTTP2_DATA:
      {
        LOG_TRACE_FMT("Data frame: {}", frame->headers.cat);
        if (stream_data->id == frame->hd.stream_id)
        {
          // TODO: Is this the right place to this?
          LOG_FAIL_FMT("All headers received");
          s->handle_response(stream_data);
        }
        break;
      }
      default:
      {
        // TODO: Support other frame types
        break;
      }
    }
    return 0;
  }

  static int on_begin_headers_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("on_begin_headers_callback");

    auto* s = reinterpret_cast<Session*>(user_data);
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
    LOG_TRACE_FMT("on_begin_headers_callback_client: {}", frame->hd.type);

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
    LOG_TRACE_FMT("on_header_callback: {}:{}", k, v);

    auto* s = reinterpret_cast<Session*>(user_data);
    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

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
    LOG_TRACE_FMT("on_header_callback_client: {}:{}", k, v);

    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

    if (k == http2::headers::STATUS)
    {
      stream_data->status =
        HTTP_STATUS_OK; // TODO: Status conversion from string to http_status
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
    LOG_TRACE_FMT("on_data_callback: {}", stream_id);

    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));

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
    LOG_TRACE_FMT("on_data_callback_client: {}", stream_id);

    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));

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
    LOG_TRACE_FMT("on_stream_close_callback: {}, {}", stream_id, error_code);

    // TODO: Close stream_data correctly
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
      "on_data_source_read_length_callback: {}, {}, allowed [1, "
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

      // TODO: Configurable by operator
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

    void send_response(
      StreamId stream_id,
      http_status status,
      const http::HeaderMap& headers,
      std::vector<uint8_t>&& body)
    {
      LOG_TRACE_FMT(
        "http2::send_response: {} - {}", headers.size(), body.size());

      std::string body_size = std::to_string(body.size());
      std::vector<nghttp2_nv> hdrs;
      auto status_str = fmt::format(
        "{}", static_cast<std::underlying_type<http_status>::type>(status));
      hdrs.emplace_back(make_nv(http2::headers::STATUS, status_str.data()));
      hdrs.emplace_back(
        make_nv(http::headers::CONTENT_LENGTH, body_size.data()));
      for (auto& [k, v] : headers)
      {
        hdrs.emplace_back(make_nv(k.data(), v.data()));
      }

      auto* stream_data = reinterpret_cast<StreamData*>(
        nghttp2_session_get_stream_user_data(session, stream_id));
      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("stream not found!");
        return;
      }
      stream_data->response_body = std::move(body);

      // Note: response body is currently stored in StreamData, accessible from
      // read_callback
      nghttp2_data_provider prov;
      prov.read_callback = read_callback;

      int rv = nghttp2_submit_response(
        session, stream_id, hdrs.data(), hdrs.size(), &prov);
      if (rv != 0)
      {
        throw std::logic_error(
          fmt::format("nghttp2_submit_response error: {}", rv));
      }
    }

    virtual void handle_request(StreamData* stream_data) override
    {
      LOG_TRACE_FMT("http2::ServerSession: handle_request");

      proc.handle_request(
        stream_data->id,
        stream_data->verb.get_http_method().value(),
        stream_data->url,
        std::move(stream_data->headers),
        std::move(stream_data->request_body));
    }

    void handle_response(StreamData* stream_data) override
    {
      throw std::logic_error("Not implemented");
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
      const std::string& route,
      const http::HeaderMap& headers,
      std::vector<uint8_t>&& body)
    {
      std::vector<nghttp2_settings_entry> settings = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1}};

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
        make_nv(http2::headers::METHOD, "POST")); // TODO: Make configurable
      hdrs.emplace_back(make_nv(http2::headers::PATH, route.data()));
      hdrs.emplace_back(make_nv(":scheme", "https"));
      hdrs.emplace_back(make_nv(":authority", "localhost:8080"));
      for (auto const& [k, v] : headers)
      {
        hdrs.emplace_back(make_nv(k.data(), v.data()));
      }

      auto stream_data = std::make_shared<StreamData>(0);
      add_stream(stream_data);

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
      }

      stream_data->id = stream_id;

      auto rc = nghttp2_session_send(session);
      if (rc < 0)
      {
        throw std::logic_error(
          fmt::format("nghttp2_session_send: {}", nghttp2_strerror(rc)));
      }

      LOG_FAIL_FMT("Successfully sent request with stream id: {}", stream_id);
    }

    virtual void handle_request(StreamData* stream_data) override
    {
      throw std::logic_error("Not implemented");
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

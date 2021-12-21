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

namespace http2
{
  using StreamId = int32_t;

  static ssize_t send_callback(
    nghttp2_session* session,
    const uint8_t* data,
    size_t length,
    int flags,
    void* user_data);
  static int on_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_begin_headers_callback(
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
  static int on_data_callback(
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

  static nghttp2_nv make_nv(const std::string& key, const std::string& value)
  {
    // TODO: Investigate no copy flags here
    return {
      (uint8_t*)key.c_str(), // TODO: ugly cast
      (uint8_t*)value.c_str(),
      key.size(),
      value.size(),
      NGHTTP2_NV_FLAG_NONE};
  }

  struct StreamData
  {
    StreamId id;
    http::HeaderMap headers;
    std::string url;
    ccf::RESTVerb verb;
    std::vector<uint8_t> request_body;
    std::vector<uint8_t> response_body;

    StreamData(StreamId id_) : id(id_) {}
  };

  class Session
  {
  protected:
    nghttp2_session* session;
    std::list<std::shared_ptr<StreamData>> streams;

  public:
    Session()
    {
      LOG_TRACE_FMT("Created HTTP2 session");
      nghttp2_session_callbacks* callbacks;
      nghttp2_session_callbacks_new(&callbacks);
      nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
      nghttp2_session_callbacks_set_on_frame_recv_callback(
        callbacks, on_frame_recv_callback);
      nghttp2_session_callbacks_set_on_begin_headers_callback(
        callbacks, on_begin_headers_callback);

      nghttp2_session_callbacks_set_on_header_callback(
        callbacks, on_header_callback);

      nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
        callbacks, on_data_callback);

      nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

      nghttp2_session_server_new(&session, callbacks, this);

      nghttp2_session_callbacks_del(callbacks);
    }

    void add_stream(const std::shared_ptr<StreamData>& stream_data)
    {
      streams.push_back(stream_data);
    }

    virtual void send(const uint8_t* data, size_t length)
    {
      LOG_TRACE_FMT("http2::Session send: {}", length);
      // auto rv = nghttp2_session_send(session);
      // LOG_FAIL_FMT("http::Session send rv: {}", rv);
    }

    void recv(const uint8_t* data, size_t size)
    {
      LOG_TRACE_FMT("http2::Session recv: {}", size);
      auto readlen = nghttp2_session_mem_recv(session, data, size);
      LOG_FAIL_FMT("http::Session recv readlen: {}", readlen);
      if (readlen < 0)
      {
        return;
      }

      auto rc = nghttp2_session_send(session);
      LOG_FAIL_FMT("nghttp2_session_send: {}", rc);
    }

    virtual void handle_request(StreamData* stream_data) = 0;
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

    LOG_FAIL_FMT("resp body size: {}", response_body.size());

    memcpy(buf, response_body.data(), response_body.size());
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return response_body.size();
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
        // on_stream_close_callback. Check that stream_data still alive.
        if (!stream_data)
        {
          LOG_FAIL_FMT("No stream_data");
          return 0;
        }

        /* Check that the client request has finished */
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
          LOG_FAIL_FMT("End of stream_data flag");
          LOG_FAIL_FMT("StreamData id: {}", frame->hd.stream_id);
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
        "Could not set stream_data user data: {}", frame->hd.stream_id));
    }

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

    auto* s = reinterpret_cast<Session*>(user_data);
    auto* stream_data = reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

    LOG_TRACE_FMT("on_header_callback: {}:{}", k, v);

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

    LOG_FAIL_FMT("request body size: {}", stream_data->request_body.size());
    return 0;
  }

  static int on_stream_close_callback(
    nghttp2_session* session,
    StreamId stream_id,
    uint32_t error_code,
    void* user_data)
  {
    LOG_TRACE_FMT("on_stream_close_callback: {}", stream_id);
    // TODO: Close stream_data correctly
    return 0;
  }

  class ServerSession : public Session
  {
  private:
    http::RequestProcessor& proc;
    enclave::Endpoint& endpoint;

  public:
    ServerSession(http::RequestProcessor& proc_, enclave::Endpoint& endpoint_) :
      proc(proc_),
      endpoint(endpoint_)
    {
      LOG_TRACE_FMT("Initialising HTTP2 Server Session");

      // TODO: Should be configurable by operator
      std::vector<nghttp2_settings_entry> settings = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};

      auto rv = nghttp2_submit_settings(
        session, NGHTTP2_FLAG_NONE, settings.data(), settings.size());
    }

    void send_response(
      StreamId stream_id,
      const http::HeaderMap& headers,
      std::vector<uint8_t>&& body)
    {
      LOG_TRACE_FMT(
        "http2::send_response: {} - {}", headers.size(), body.size());

      std::vector<nghttp2_nv> hdrs;
      hdrs.emplace_back(
        make_nv(http2::headers::STATUS, "200")); // TODO: Support status
      hdrs.emplace_back(
        make_nv(http::headers::CONTENT_LENGTH, fmt::format("{}", body.size())));
      for (auto& [k, v] : headers)
      {
        hdrs.emplace_back(make_nv(k, v));
      }

      auto* stream_data = reinterpret_cast<StreamData*>(
        nghttp2_session_get_stream_user_data(session, stream_id));
      if (stream_data == nullptr)
      {
        LOG_FAIL_FMT("StreamData not found!");
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

    virtual void send(const uint8_t* data, size_t length) override
    {
      LOG_TRACE_FMT("http2::ServerSession send: {}", length);
      std::vector<uint8_t> resp = {
        data, data + length}; // TODO: Remove extra copy
      endpoint.send(std::move(resp));
    }

    virtual void handle_request(StreamData* stream_data) override
    {
      LOG_TRACE_FMT("http2::ServerSession: handle_request");

      // TODO: Support HTTP method and body
      proc.handle_request(
        stream_data->id,
        stream_data->verb.get_http_method().value(),
        stream_data->url,
        std::move(stream_data->headers),
        std::move(stream_data->request_body));
    }
  };

  class ClientSession : public Session
  {
    // TODO: Unimplemented
  public:
    ClientSession() = default;

    virtual void handle_request(StreamData* stream_data) override
    {
      throw std::logic_error("Unimplemented");
    }
  };
}

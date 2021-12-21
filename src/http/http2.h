// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/endpoint.h" // TODO: Not great!
#include "http_builder.h"
#include "http_proc.h"

#include <list>
#include <memory>
#include <nghttp2/nghttp2.h>

namespace http2
{
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

  struct Stream
  {
    uint32_t id;
    http::HeaderMap headers;
    std::string url;

    Stream(uint32_t id_) : id(id_) {}
  };

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
  static int on_stream_close_callback(
    nghttp2_session* session,
    int32_t stream_id,
    uint32_t error_code,
    void* user_data);

  class Session
  {
  protected:
    nghttp2_session* session;
    std::list<std::shared_ptr<Stream>> streams;

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

      nghttp2_session_callbacks_set_on_stream_close_callback(
        callbacks, on_stream_close_callback);

      nghttp2_session_server_new(&session, callbacks, this);

      nghttp2_session_callbacks_del(callbacks);
    }

    void add_stream(const std::shared_ptr<Stream>& stream)
    {
      streams.push_back(stream);
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

    virtual void handle_request(Stream* stream) = 0;
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
    int32_t stream_id,
    uint8_t* buf,
    size_t length,
    uint32_t* data_flags,
    nghttp2_data_source* source,
    void* user_data)
  {
    LOG_TRACE_FMT("read_callback: {}", length);

    std::string resp = "Hello there";

    // auto resp_body = reinterpret_cast<std::vector<uint8_t>*>(source);

    // LOG_FAIL_FMT("resp body size: {}", resp_body->size());

    memcpy(buf, resp.data(), resp.size());
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return resp.size();
  }

  static int on_request_recv(
    nghttp2_session* session, Session* session_data, Stream* stream_data)
  {
    LOG_TRACE_FMT("on_request_recv");

    std::vector<nghttp2_nv> hdrs;
    hdrs.emplace_back(make_nv(":status", "200"));

    nghttp2_data_provider prov;
    prov.read_callback = read_callback;

    int rv = nghttp2_submit_response(
      session, stream_data->id, hdrs.data(), hdrs.size(), &prov);
    LOG_FAIL_FMT("nghttp2_submit_response: {}", rv);
    if (rv != 0)
    {
      LOG_FAIL_FMT("Error sending response: {}", rv);
      return -1;
    }

    return 0;
  }

  static int on_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("on_frame_recv_callback, type: {}", frame->hd.type);
    auto* s = reinterpret_cast<Session*>(user_data);
    Stream* stream;

    switch (frame->hd.type)
    {
      case NGHTTP2_DATA:
      case NGHTTP2_HEADERS:
        /* Check that the client request has finished */
        LOG_FAIL_FMT("Frame data or headers");
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
          LOG_FAIL_FMT("End of stream flag");
          LOG_FAIL_FMT("Stream id: {}", frame->hd.stream_id);
          stream = reinterpret_cast<Stream*>(
            nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));
          /* For DATA and HEADERS frame, this callback may be called after
             on_stream_close_callback. Check that stream still alive. */
          if (!stream)
          {
            LOG_FAIL_FMT("No stream!");
            return 0;
          }
          // return on_request_recv(session, s, stream);
          s->handle_request(stream);
        }
        break;
      default:
        break;
    }

    return 0;
  }

  static int on_begin_headers_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("on_begin_headers_callback");
    auto* s = reinterpret_cast<Session*>(user_data);

    auto stream = std::make_shared<Stream>(frame->hd.stream_id);
    s->add_stream(stream);
    nghttp2_session_set_stream_user_data(
      session, frame->hd.stream_id, stream.get());

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
    LOG_TRACE_FMT(
      "on_header_callback: {}:{}",
      std::string(name, name + namelen),
      std::string(value, value + valuelen));

    auto* s = reinterpret_cast<Session*>(user_data);
    auto* stream = reinterpret_cast<Stream*>(
      nghttp2_session_get_stream_user_data(session, frame->hd.stream_id));

    auto k = std::string(name, name + namelen);
    auto v = std::string(value, value + valuelen);

    if (k == ":path")
    {
      stream->url = v;
    }
    else if (k == ":method")
    {
      // stream->
      // TODO: Support method!
    }
    else
    {
      stream->headers.emplace(k, v);
    }

    return 0;
  }

  static int on_stream_close_callback(
    nghttp2_session* session,
    int32_t stream_id,
    uint32_t error_code,
    void* user_data)
  {
    LOG_TRACE_FMT("on_stream_close_callback: {}", stream_id);
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
      LOG_TRACE_FMT("Initialise HTTP2 Server Session");

      // TODO: Should be configurable by operator
      std::vector<nghttp2_settings_entry> settings = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
      auto rv = nghttp2_submit_settings(
        session, NGHTTP2_FLAG_NONE, settings.data(), settings.size());
    }

    void send_response(
      const http::HeaderMap& headers, const std::vector<uint8_t>& body)
    {
      LOG_TRACE_FMT(
        "http2::send_response: {} - {}", headers.size(), body.size());

      std::vector<nghttp2_nv> hdrs;
      hdrs.emplace_back(make_nv(":status", "200"));
      for (auto& [k, v] : headers)
      {
        hdrs.emplace_back(make_nv(k, v));
      }

      nghttp2_data_provider prov;
      // prov.source.ptr = (void*)&body; // TODO: Ugly cast!
      prov.read_callback = read_callback;

      // TODO: stream ID is hardcoded! :(
      int rv =
        nghttp2_submit_response(session, 1, hdrs.data(), hdrs.size(), &prov);
    }

    virtual void send(const uint8_t* data, size_t length) override
    {
      LOG_TRACE_FMT("http2::ServerSession send: {}", length);
      std::vector<uint8_t> resp = {
        data, data + length}; // TODO: Remove extra copy
      endpoint.send(std::move(resp));
    }

    virtual void handle_request(Stream* stream) override
    {
      LOG_TRACE_FMT("http2::ServerSession: handle_request");

      // TODO: Support HTTP method and body
      proc.handle_request(
        HTTP_GET, stream->url, std::move(stream->headers), {});
    }
  };

  class ClientSession : public Session
  {
    // TODO: Unimplemented
  public:
    ClientSession() = default;

    virtual void handle_request(Stream* stream) override
    {
      throw std::logic_error("Unimplemented");
    }
  };
}

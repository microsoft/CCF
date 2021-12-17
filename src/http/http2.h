// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <list>
#include <memory>
#include <nghttp2/nghttp2.h>

namespace http2
{
  struct Stream
  {
    uint32_t id;
  };

  struct Session
  {
    int64_t id;

    nghttp2_session* session;
    std::list<std::shared_ptr<Stream>> streams;

    Session(int64_t session_id) : id(session_id)
    {
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

    static ssize_t send_callback(
      nghttp2_session* session,
      const uint8_t* data,
      size_t length,
      int flags,
      void* user_data)
    {
      LOG_TRACE_FMT("send_callback: {}", length);
      return 0;
    }

    static int on_frame_recv_callback(
      nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
    {
      LOG_TRACE_FMT("on_frame_recv_callback");
      return 0;
    }

    static int on_begin_headers_callback(
      nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
    {
      LOG_TRACE_FMT("on_begin_headers_callback");
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
      LOG_TRACE_FMT("on_header_callback: {}", namelen);
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
  };

}

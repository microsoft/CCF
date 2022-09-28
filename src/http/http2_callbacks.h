// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "http2_types.h"

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
    LOG_TRACE_FMT("http2::read_callback: {}", length);

    auto* stream_data = get_stream_data(session, stream_id);

    auto& body = stream_data->body;

    if (body.size() > 0)
    {
      if (length < body.size())
      {
        throw std::runtime_error("Read too large");
      }

      // Note: Explore zero-copy alternative (NGHTTP2_DATA_FLAG_NO_COPY)
      memcpy(buf, body.data(), body.size());
    }

    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    if (!stream_data->trailers.empty())
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
        *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      }
    }

    return body.size();
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

    auto& body = stream_data->body;

    // Note: Explore zero-copy alternative (NGHTTP2_DATA_FLAG_NO_COPY)
    size_t to_read =
      std::min(body.size() - stream_data->current_offset, length);
    LOG_TRACE_FMT(
      "Request body size: {}, offset: {}, to_read: {}",
      body.size(),
      stream_data->current_offset,
      to_read);
    if (body.size() > 0)
    {
      memcpy(buf, body.data() + stream_data->current_offset, to_read);
      stream_data->current_offset += to_read;
    }
    if (stream_data->current_offset >= body.size())
    {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      stream_data->current_offset = 0;
      body.clear();
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
          s->handle_completed(stream_data);
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

    auto* stream_data = get_stream_data(session, frame->hd.stream_id);
    stream_data->headers.emplace(k, v);

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

    stream_data->body.insert(stream_data->body.end(), data, data + len);

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

    auto* s = get_session(user_data);

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
}

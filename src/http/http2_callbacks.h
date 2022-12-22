// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/http_configuration.h"
#include "http/http_exceptions.h"
#include "http2_types.h"
#include "http2_utils.h"

namespace http2
{
  static ssize_t read_outgoing_callback(
    nghttp2_session* session,
    StreamId stream_id,
    uint8_t* buf,
    size_t length,
    uint32_t* data_flags,
    nghttp2_data_source* source,
    void* user_data)
  {
    auto* stream_data = get_stream_data(session, stream_id);
    if (stream_data->outgoing.state == StreamResponseState::Uninitialised)
    {
      LOG_FAIL_FMT(
        "http2::read_outgoing_callback error: unexpected state {}",
        stream_data->outgoing.state);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    auto& body = stream_data->outgoing.body.ro_data();
    size_t to_read = std::min(body.size(), length);

    if (
      to_read == 0 &&
      stream_data->outgoing.state == StreamResponseState::Streaming)
    {
      // Early out: when streaming, avoid calling this callback
      // repeatedly when there no data to read
      return NGHTTP2_ERR_DEFERRED;
    }

    if (to_read > 0)
    {
      memcpy(buf, body.data(), to_read);
      body = body.subspan(to_read);
    }

    if (stream_data->outgoing.state == StreamResponseState::Closing)
    {
      if (body.empty())
      {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      }

      if (stream_data->outgoing.has_trailers)
      {
        *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      }
    }

    return to_read;
  }

  static int on_begin_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame_hd* hd, void* user_data)
  {
    const auto& stream_id = hd->stream_id;
    LOG_TRACE_FMT(
      "http2::on_begin_frame_recv_callback, type: {}, stream_id: {}",
      hd->type,
      stream_id);

    // nghttp2 does not handle
    // https://www.rfc-editor.org/rfc/rfc7540#section-5.1.1 (see
    // https://github.com/nghttp2/nghttp2/issues/1300)
    // > An endpoint that receives an unexpected stream identifier MUST
    // > respond with a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
    //
    // So can catch this case early in this callback by making sure that _new_
    // stream ids are not less than the most recent stream id on this session.
    auto* p = get_parser(user_data);
    if (
      stream_id != DEFAULT_STREAM_ID && p->get_stream(stream_id) == nullptr &&
      hd->type == NGHTTP2_HEADERS)
    {
      if (stream_id < p->get_last_stream_id())
      {
        LOG_TRACE_FMT(
          "http2::on_begin_frame_recv_callback: cannot process stream id {} "
          "< last stream id {}",
          stream_id,
          p->get_last_stream_id());
        return NGHTTP2_ERR_PROTO;
      }

      p->create_stream(stream_id);
    }

    return 0;
  }

  static int on_frame_recv_callback(
    nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    LOG_TRACE_FMT("http2::on_frame_recv_callback, type: {}", frame->hd.type);

    const auto stream_id = frame->hd.stream_id;
    auto* stream_data = get_stream_data(session, stream_id);

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
          auto* p = get_parser(user_data);
          p->handle_completed(stream_id, stream_data);
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
    const auto& stream_id = frame->hd.stream_id;

    auto* p = get_parser(user_data);

    auto stream_data = p->get_stream(stream_id);
    if (stream_data == nullptr)
    {
      // Streams are created in on_begin_frame_recv_callback
      throw std::logic_error(
        fmt::format("Stream {} should already exist", stream_id));
    }

    auto rc = nghttp2_session_set_stream_user_data(
      session, stream_id, stream_data.get());
    if (rc != 0)
    {
      throw std::logic_error(fmt::format(
        "HTTP/2: Could not set user data for stream {}: {}",
        stream_id,
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
    const auto& stream_id = frame->hd.stream_id;
    auto k = std::string(name, name + namelen);
    auto v = std::string(value, value + valuelen);
    LOG_TRACE_FMT("http2::on_header_callback: {}, {}:{}", stream_id, k, v);

    auto* p = get_parser(user_data);
    const auto& configuration = p->get_configuration();

    auto const& max_header_size =
      configuration.max_header_size.value_or(http::default_max_header_size);
    if (namelen > max_header_size)
    {
      throw http::RequestHeaderTooLargeException(
        fmt::format(
          "Header key for '{}' is too large (max size allowed: {})",
          k,
          max_header_size),
        stream_id);
    }

    if (valuelen > max_header_size)
    {
      throw http::RequestHeaderTooLargeException(
        fmt::format(
          "Header value for '{}' is too large (max size allowed: {})",
          v,
          max_header_size),
        stream_id);
    }

    auto* stream_data = get_stream_data(session, stream_id);
    const auto max_headers_count =
      configuration.max_headers_count.value_or(http::default_max_headers_count);
    if (stream_data->incoming.headers.size() >= max_headers_count)
    {
      throw http::RequestHeaderTooLargeException(
        fmt::format(
          "Too many headers (max number allowed: {})", max_headers_count),
        stream_id);
    }

    stream_data->incoming.headers.emplace(k, v);

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
    LOG_TRACE_FMT("http2::on_data_callback: {}, {} bytes", stream_id, len);

    auto* stream_data = get_stream_data(session, stream_id);
    auto* p = get_parser(user_data);
    const auto& configuration = p->get_configuration();

    stream_data->incoming.body.insert(
      stream_data->incoming.body.end(), data, data + len);

    auto const& max_body_size =
      configuration.max_body_size.value_or(http::default_max_body_size);
    if (stream_data->incoming.body.size() > max_body_size)
    {
      throw http::RequestPayloadTooLargeException(
        fmt::format(
          "HTTP request body is too large (max size allowed: {})",
          max_body_size),
        stream_id);
    }

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

    auto* p = get_parser(user_data);
    p->destroy_stream(stream_id);

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
    auto* p = get_parser(user_data);
    const auto& configuration = p->get_configuration();
    const auto& max_frame_size =
      configuration.max_frame_size.value_or(http::default_max_frame_size);

    LOG_TRACE_FMT(
      "http2::on_data_source_read_length_callback: {}, {}, allowed [1, "
      "min({},{},{})]",
      stream_id,
      max_frame_size,
      session_remote_window_size,
      stream_remote_window_size,
      remote_max_frame_size);

    return max_frame_size;
  }

  static int on_error_callback(
    nghttp2_session* session,
    int lib_error_code,
    const char* msg,
    size_t len,
    void* user_data)
  {
    LOG_DEBUG_FMT("HTTP/2 error: {}", std::string(msg, msg + len));
    return 0;
  }
}

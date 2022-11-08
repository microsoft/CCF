// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_header_map.h"
#include "ccf/http_status.h"
#include "ccf/rest_verb.h"
#include "http_builder.h"

#include <list>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <string>
#include <vector>

namespace http2
{
  using StreamId = int32_t;

  constexpr static size_t max_data_read_size = 1 << 20;

  // struct DataSource
  // {
  //   std::span<const uint8_t> body = {};
  //   bool end_data = true;
  //   bool end_stream = true;
  // };

  // Used to keep track of response state between nghttp2 callbacks and to
  // differentiate unary from streaming responses
  enum class StreamResponseState
  {
    Closing = 0, // Unary or last message in stream
    AboutToStream, // Initial response (headers) to stream response
    Streaming // Response streaming messages
  };

  struct StreamData
  {
    // Request
    http::HeaderMap headers; // Only used for incoming headers

    // Response
    StreamResponseState response_state = StreamResponseState::Closing;
    std::vector<uint8_t> body;
    std::span<const uint8_t> body_s; // TODO: Rename
    // size_t current_offset = 0;
    http::HeaderMap trailers; // Only used for outgoing trailers
  };

  class AbstractParser
  {
  public:
    virtual ~AbstractParser() = default;
    virtual void handle_completed(
      StreamId stream_id, StreamData* stream_data) = 0;
    virtual std::shared_ptr<StreamData> create_stream(StreamId stream_id) = 0;
    virtual void destroy_stream(StreamId stream_id) = 0;
  };

  // Functions to create HTTP2 headers
  static nghttp2_nv make_nv(const uint8_t* key, const uint8_t* value)
  {
    // Note: Investigate no copy flags here
    return {
      const_cast<uint8_t*>(key),
      const_cast<uint8_t*>(value),
      strlen((char*)key),
      strlen((char*)value),
      NGHTTP2_NV_FLAG_NONE};
  }

  static inline nghttp2_nv make_nv(const char* key, const char* value)
  {
    return make_nv((uint8_t*)key, (uint8_t*)value);
  }

  static inline AbstractParser* get_parser(void* user_data)
  {
    return reinterpret_cast<AbstractParser*>(user_data);
  }

  static inline StreamData* get_stream_data(
    nghttp2_session* session, StreamId stream_id)
  {
    return reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));
  }
}
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
    StreamId id;

    // Request
    http::HeaderMap headers;
    std::string url;
    ccf::RESTVerb verb;
    std::vector<uint8_t> request_body;

    // Response
    StreamResponseState response_state = StreamResponseState::Closing;
    http_status status;
    std::vector<uint8_t> response_body;
    size_t current_offset = 0;
    http::HeaderMap trailers;

    StreamData(StreamId id_) : id(id_) {}
  };

  class AbstractSession
  {
  public:
    virtual ~AbstractSession() = default;
    virtual void send(const uint8_t* data, size_t length) = 0;
    virtual void handle_request(StreamData* stream_data) = 0;
    virtual void handle_response(StreamData* stream_data) = 0;
    virtual void add_stream(const std::shared_ptr<StreamData>& stream_data) = 0;
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

  static nghttp2_nv make_nv(const char* key, const char* value)
  {
    return make_nv((uint8_t*)key, (uint8_t*)value);
  }

  AbstractSession* get_session(void* user_data)
  {
    return reinterpret_cast<AbstractSession*>(user_data);
  }

  StreamData* get_stream_data(nghttp2_session* session, StreamId stream_id)
  {
    return reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));
  }
}
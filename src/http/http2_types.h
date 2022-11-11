// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/http_header_map.h"
#include "ccf/http_status.h"
#include "ccf/rest_verb.h"
#include "http_builder.h"

#include <list>
#include <memory>
#include <nghttp2/nghttp2.h>
#include <optional>
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
    Uninitialised = 0, // State still unset
    Closing, // Unary or last message in stream
    AboutToStream, // Initial response (headers) to stream response
    Streaming // Response streaming messages
  };

  class DataSource
  {
    // Utility class to consume data from underlying data vector in chunks from
    // nghttp2_data_source_read_callback
  private:
    std::vector<uint8_t> data;

    std::span<const uint8_t> span;

  public:
    DataSource() = default;

    DataSource(std::vector<uint8_t>&& data_) :
      data(std::move(data_)),
      span(data)
    {}

    std::span<const uint8_t>& ro_data()
    {
      return span;
    }
  };

  struct StreamData
  {
    struct Incoming
    {
      http::HeaderMap headers;
      std::vector<uint8_t> body;
    };
    Incoming incoming;

    struct Outgoing
    {
      StreamResponseState state = StreamResponseState::Uninitialised;
      bool has_trailers = false;
      DataSource body;
    };
    Outgoing outgoing;
  };

  class AbstractParser
  {
  public:
    virtual ~AbstractParser() = default;
    virtual void handle_completed(
      StreamId stream_id, StreamData* stream_data) = 0;
    virtual std::shared_ptr<StreamData> get_stream(StreamId stream_id) = 0;
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

  static inline std::optional<std::string> make_trailer_header_value(
    const http::HeaderMap& trailers)
  {
    if (trailers.empty())
    {
      return std::nullopt;
    }

    using HeaderKeysIt = nonstd::KeyIterator<http::HeaderMap::const_iterator>;
    const auto trailer_header_val = fmt::format(
      "{}",
      fmt::join(
        HeaderKeysIt(trailers.begin()), HeaderKeysIt(trailers.end()), ","));

    return trailer_header_val;
  }

  static inline StreamData* get_stream_data(
    nghttp2_session* session, StreamId stream_id)
  {
    return reinterpret_cast<StreamData*>(
      nghttp2_session_get_stream_user_data(session, stream_id));
  }
}
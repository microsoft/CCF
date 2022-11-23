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
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/http_header_map.h"

#include <nghttp2/nghttp2.h>
#include <optional>

namespace http2
{
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
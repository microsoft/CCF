// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "http2_types.h"

#include <stdexcept>

namespace http
{
  class RequestTooLargeException : public std::runtime_error
  {
  private:
    http2::StreamId stream_id;

  public:
    RequestTooLargeException(
      const std::string& msg,
      http2::StreamId stream_id = http2::DEFAULT_STREAM_ID) :
      std::runtime_error(msg),
      stream_id(stream_id)
    {}

    http2::StreamId get_stream_id() const
    {
      return stream_id;
    }
  };

  class RequestPayloadTooLargeException : public RequestTooLargeException
  {
  public:
    RequestPayloadTooLargeException(
      const std::string& msg, http2::StreamId stream_id = 0) :
      RequestTooLargeException(msg, stream_id)
    {}
  };

  class RequestHeaderTooLargeException : public RequestTooLargeException
  {
  public:
    RequestHeaderTooLargeException(
      const std::string& msg,
      http2::StreamId stream_id = http2::DEFAULT_STREAM_ID) :
      RequestTooLargeException(msg, stream_id)
    {}
  };
}
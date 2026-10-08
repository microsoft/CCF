// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <stdexcept>

namespace http
{
  class RequestTooLargeException : public std::runtime_error
  {
  public:
    explicit RequestTooLargeException(const std::string& msg) :
      std::runtime_error(msg)
    {}
  };

  class RequestPayloadTooLargeException : public RequestTooLargeException
  {
  public:
    explicit RequestPayloadTooLargeException(const std::string& msg) :
      RequestTooLargeException(msg)
    {}
  };

  class RequestTargetTooLongException : public RequestTooLargeException
  {
  public:
    explicit RequestTargetTooLongException(const std::string& msg) :
      RequestTooLargeException(msg)
    {}
  };

  class RequestHeaderTooLargeException : public RequestTooLargeException
  {
  public:
    explicit RequestHeaderTooLargeException(const std::string& msg) :
      RequestTooLargeException(msg)
    {}
  };
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstdint>
#include <ravl/http_client.h>

namespace ravl
{
  HTTPResponse HTTPRequest::execute(size_t request_timeout, bool verbose)
  {
    throw std::runtime_error("synchronous url requests not supported");
  }
}
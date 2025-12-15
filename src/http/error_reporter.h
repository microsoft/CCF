// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/rpc_context.h"

namespace http
{
  class ErrorReporter
  {
  public:
    virtual ~ErrorReporter() = default;
    virtual void report_parsing_error(const ccf::ListenInterfaceID&) = 0;
    virtual void report_request_payload_too_large_error(
      const ccf::ListenInterfaceID&) = 0;
    virtual void report_request_header_too_large_error(
      const ccf::ListenInterfaceID&) = 0;
  };
}
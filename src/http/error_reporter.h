// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "tls/msg_types.h"

namespace http
{
  class ErrorReporter
  {
  public:
    virtual ~ErrorReporter() {}
    virtual void report_parsing_error(tls::ConnID) = 0;
    virtual void report_request_payload_too_large_error(tls::ConnID) = 0;
    virtual void report_request_header_too_large_error(tls::ConnID) = 0;
  };
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

namespace ccf
{
  enum LoggerLevel
  {
    TRACE,
    DEBUG, // events useful for debugging
    INFO, // important events that should be logged even in release mode
    FAIL, // survivable failures that should always be logged
    FATAL, // fatal errors that may be non-recoverable
    MAX_LOG_LEVEL
  };
}

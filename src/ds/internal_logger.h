// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"

#include <iostream>
#include <string_view>

// Defines the LOG_*_FMT macros that should be used for logging by
// framework-internal components. Alternatively, replace with macros which add a
// system-specific tag.

namespace ccf::logger
{
  inline void write_fatal_diagnostic(std::string_view message)
  {
    // A single insertion keeps concurrent diagnostics on separate lines, since
    // std::cerr is synchronised with stdio and each write takes its lock.
    std::cerr << fmt::format("Fatal error: {}\n", message) << std::flush;
  }

#define LOG_TRACE_FMT CCF_LOG_FMT(TRACE, "")
#define LOG_DEBUG_FMT CCF_LOG_FMT(DEBUG, "")
#define LOG_INFO_FMT CCF_LOG_FMT(INFO, "")
#define LOG_FAIL_FMT CCF_LOG_FMT(FAIL, "")
#define LOG_FATAL_FMT CCF_LOG_FMT(FATAL, "")
}

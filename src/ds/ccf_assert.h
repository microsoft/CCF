// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "stacktrace_utils.h"

#define CCF_ASSERT_FMT_FAIL(...) \
  CCF_ASSERT(false, fmt::format(__VA_ARGS__).c_str())

#define CCF_ASSERT_FMT(expr, ...) \
  CCF_ASSERT(expr, fmt::format(__VA_ARGS__).c_str())

#ifndef NDEBUG
#  define CCF_ASSERT(expr, msg) \
    do \
    { \
      if ((expr) == 0) \
      { \
        LOG_FAIL_FMT("Assertion failed: {} {}", #expr, (msg)); \
        stacktrace::print_stacktrace(); \
        throw std::logic_error(msg); \
      } \
    } while (0)
#else
#  define CCF_ASSERT(expr, msg) ((void)0)
#endif /* NDEBUG */

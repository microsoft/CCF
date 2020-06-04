// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "ds/logger.h"

#ifndef INSIDE_ENCLAVE
#  include "stacktrace_utils.h"
#endif

#define CCF_ASSERT_FMT_FAIL(...) \
  CCF_ASSERT(false, fmt::format(__VA_ARGS__).c_str())

#define CCF_ASSERT_FMT(expr, ...) \
  CCF_ASSERT(expr, fmt::format(__VA_ARGS__).c_str())

#ifndef INSIDE_ENCLAVE
#  ifndef NDEBUG
#    define CCF_ASSERT(expr, msg) \
      do \
      { \
        if ((expr) == 0) \
        { \
          LOG_INFO << " Assertion failed: " << #expr << " " << (msg) << "\n"; \
          logger::print_stacktrace(); \
          throw std::logic_error(msg); \
        } \
      } while (0)
#  else
#    define CCF_ASSERT(expr, msg) ((void)0)
#  endif /* NDEBUG */

#  define PBFT_FAIL(msg) \
    do \
    { \
      LOG_INFO << " FATAL_ERROR: " << (msg) << "\n"; \
      logger::print_stacktrace(); \
      std::terminate(); \
    } while (0)
#else
#  ifndef NDEBUG
#    define CCF_ASSERT(expr, msg) \
      do \
      { \
        if ((expr) == 0) \
        { \
          LOG_INFO << " Assertion failed: " << #expr << " " << (msg) << "\n"; \
          throw std::logic_error(msg); \
        } \
      } while (0)
#  else
#    define CCF_ASSERT(expr, msg) ((void)0)
#  endif /* NDEBUG */

#  define PBFT_FAIL(msg) \
    do \
    { \
      LOG_INFO << " FATAL_ERROR: " << (msg) << "\n"; \
      std::terminate(); \
    } while (0)
#endif

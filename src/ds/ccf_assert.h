// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#pragma once

#include "ds/logger.h"
#include "stacktrace_utils.h"

#define CCF_ASSERT_FMT_FAIL(...) \
  CCF_ASSERT(false, fmt::format(__VA_ARGS__).c_str())

#define CCF_ASSERT_FMT(expr, ...) \
  CCF_ASSERT(expr, fmt::format(__VA_ARGS__).c_str())

<<<<<<< HEAD
#ifndef NDEBUG
#  define CCF_ASSERT(expr, msg) \
=======
#ifndef INSIDE_ENCLAVE
#  ifndef NDEBUG
#    define CCF_ASSERT(expr, msg) \
      do \
      { \
        if ((expr) == 0) \
        { \
          LOG_FAIL_FMT("Assertion failed: {} {}", #expr, (msg)); \
          stacktrace::print_stacktrace(); \
          throw std::logic_error(msg); \
        } \
      } while (0)
#  else
#    define CCF_ASSERT(expr, msg) ((void)0)
#  endif /* NDEBUG */

#  define CCF_FAIL(msg) \
>>>>>>> stuff
    do \
    { \
      if ((expr) == 0) \
      { \
<<<<<<< HEAD
        LOG_FAIL_FMT("Assertion failed: {} {}", #expr, (msg)); \
        stacktrace::print_stacktrace(); \
        throw std::logic_error(msg); \
      } \
=======
        if ((expr) == 0) \
        { \
          LOG_FAIL_FMT("Assertion failed: {} {}", #expr, (msg)); \
          throw std::logic_error(msg); \
        } \
      } while (0)
#  else
#    define CCF_ASSERT(expr, msg) ((void)0)
#  endif /* NDEBUG */

#  define CCF_FAIL(msg) \
    do \
    { \
      LOG_FAIL_FMT("FATAL_ERROR: {}", (msg)); \
      std::terminate(); \
>>>>>>> stuff
    } while (0)
#else
#  define CCF_ASSERT(expr, msg) ((void)0)
#endif /* NDEBUG */

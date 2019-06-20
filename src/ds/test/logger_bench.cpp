// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "../logger.h"

#include <picobench/picobench.hpp>

static void log_accepted(picobench::state& s)
{
  // Swallow the output instead of printing to stdout.
  std::cout.setstate(std::ios_base::badbit);

  logger::config::level() = logger::DBG;
  picobench::scope scope(s);

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    LOG_DEBUG << "test" << std::endl;
  }

  std::cout.clear();
}

static void log_accepted_fmt(picobench::state& s)
{
  // Swallow the output instead of printing to stdout.
  std::cout.setstate(std::ios_base::badbit);

  logger::config::level() = logger::DBG;
  picobench::scope scope(s);

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    LOG_DEBUG_FMT("test");
  }

  std::cout.clear();
}

static void log_rejected(picobench::state& s)
{
  logger::config::level() = logger::FAIL;
  picobench::scope scope(s);

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    LOG_DEBUG << "test" << std::endl;
  }
}

static void log_rejected_fmt(picobench::state& s)
{
  logger::config::level() = logger::FAIL;
  picobench::scope scope(s);

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    LOG_DEBUG_FMT("test");
  }
}

const std::vector<int> sizes = {100000};

PICOBENCH_SUITE("logger");
PICOBENCH(log_accepted).iterations(sizes).samples(10);
PICOBENCH(log_accepted_fmt).iterations(sizes).samples(10);
PICOBENCH(log_rejected).iterations(sizes).samples(10);
PICOBENCH(log_rejected_fmt).iterations(sizes).samples(10);

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/internal_logger.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

enum LoggerKind
{
  None = 0x0,

  Console = 0x1,
  JSON = 0x2,

  All = 0xffff,
};

template <LoggerKind LK, bool Absorb = true>
static void prepare_loggers()
{
  ccf::logger::config::loggers().clear();

  if constexpr ((LK & LoggerKind::Console) != 0)
  {
    ccf::logger::config::loggers().emplace_back(
      std::make_unique<ccf::logger::TextConsoleLogger>());
  }

  if constexpr ((LK & LoggerKind::JSON) != 0)
  {
    ccf::logger::config::loggers().emplace_back(
      std::make_unique<ccf::logger::JsonConsoleLogger>());
  }

  if constexpr (Absorb)
  {
    // Swallow all output for duration of benchmarks
    std::cout.setstate(std::ios_base::badbit);
  }
}

static void reset_loggers()
{
  ccf::logger::config::loggers().clear();

  std::cout.clear();
}

template <LoggerKind LK, bool Absorb = true>
static void log_accepted(picobench::state& s)
{
  prepare_loggers<LK, Absorb>();

  ccf::logger::config::level() = ccf::LoggerLevel::DEBUG;
  {
    picobench::scope scope(s);

    for (size_t i = 0; i < s.iterations(); ++i)
    {
      CCF_LOG_OUT(DEBUG, "") << "test " << i << std::endl;
    }
  }

  reset_loggers();
}

template <LoggerKind LK, bool Absorb = true>
static void log_accepted_fmt(picobench::state& s)
{
  prepare_loggers<LK, Absorb>();

  ccf::logger::config::level() = ccf::LoggerLevel::DEBUG;
  {
    picobench::scope scope(s);

    for (size_t i = 0; i < s.iterations(); ++i)
    {
      LOG_DEBUG_FMT("test {}", i);
    }
  }

  reset_loggers();
}

template <LoggerKind LK, bool Absorb = true>
static void log_rejected(picobench::state& s)
{
  prepare_loggers<LK, Absorb>();

  ccf::logger::config::level() = ccf::LoggerLevel::FAIL;
  {
    picobench::scope scope(s);

    for (size_t i = 0; i < s.iterations(); ++i)
    {
      CCF_LOG_OUT(DEBUG, "") << "test " << i << std::endl;
    }
  }

  reset_loggers();
}

template <LoggerKind LK, bool Absorb = true>
static void log_rejected_fmt(picobench::state& s)
{
  prepare_loggers<LK, Absorb>();

  ccf::logger::config::level() = ccf::LoggerLevel::FAIL;
  {
    picobench::scope scope(s);

    for (size_t i = 0; i < s.iterations(); ++i)
    {
      LOG_DEBUG_FMT("test {}", i);
    }
  }

  reset_loggers();
}

const std::vector<int> sizes = {1000};

PICOBENCH_SUITE("logger");
auto console_accept = log_accepted<LoggerKind::Console>;
PICOBENCH(console_accept).iterations(sizes).samples(10);
auto console_accept_fmt = log_accepted_fmt<LoggerKind::Console>;
PICOBENCH(console_accept_fmt).iterations(sizes).samples(10);
auto console_reject = log_rejected<LoggerKind::Console>;
PICOBENCH(console_reject).iterations(sizes).samples(10);
auto console_reject_fmt = log_rejected_fmt<LoggerKind::Console>;
PICOBENCH(console_reject_fmt).iterations(sizes).samples(10);

auto json_accept = log_accepted<LoggerKind::JSON>;
PICOBENCH(json_accept).iterations(sizes).samples(10);
auto json_accept_fmt = log_accepted_fmt<LoggerKind::JSON>;
PICOBENCH(json_accept_fmt).iterations(sizes).samples(10);
auto json_reject = log_rejected<LoggerKind::JSON>;
PICOBENCH(json_reject).iterations(sizes).samples(10);
auto json_reject_fmt = log_rejected_fmt<LoggerKind::JSON>;
PICOBENCH(json_reject_fmt).iterations(sizes).samples(10);

// The enabled benchmarks are artifically cheap since they talk to a broken
// stream, skipping the cost of _actually writing something_. To compare this,
// uncomment the lines below (~3x slower)
// auto console_loud = log_accepted<LoggerKind::Console, false>;
// PICOBENCH(console_loud).iterations(sizes).samples(10);
// auto json_loud = log_accepted<LoggerKind::JSON, false>;
// PICOBENCH(json_loud).iterations(sizes).samples(10);
// auto all_loud = log_accepted<LoggerKind::All, false>;
// PICOBENCH(all_loud).iterations(sizes).samples(10);

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ringbuffer.h"

#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>

namespace logger
{
  enum Level
  {
    TRACE = 0,
    DBG, // events useful for debugging
    INFO, // important events that should be logged even in release mode
    FAIL, // important failures that should always be logged
    FATAL, // fatal errors that lead to a termination of the program/enclave
    MAX_LOG_LEVEL
  };

  class config
  {
  public:
    static constexpr const char* LevelNames[] = {
      "trace", "debug", "info", "fail", "fatal"};

    static const char* to_string(Level l)
    {
      return LevelNames[static_cast<int>(l)];
    }

    static std::optional<Level> to_level(const char* s)
    {
      for (int i = TRACE; i < MAX_LOG_LEVEL; i++)
      {
        if (std::strcmp(s, LevelNames[i]) == 0)
          return (Level)i;
      }

      return {};
    }

    static inline Level& level()
    {
      static Level the_level =
#if !defined(NDEBUG) || defined(VERBOSE_LOGGING)
        Level::TRACE
#else
        Level::INFO
#endif
        ;

      return the_level;
    }

#ifdef INSIDE_ENCLAVE
    static inline int& msg()
    {
      static int the_msg = ringbuffer::Const::msg_none;
      return the_msg;
    }

    static inline std::unique_ptr<ringbuffer::AbstractWriter>& writer()
    {
      static std::unique_ptr<ringbuffer::AbstractWriter> the_writer;
      return the_writer;
    }
#endif

    static inline bool ok(Level l)
    {
      return l >= level();
    }
  };

  class LogLine
  {
  private:
    friend struct Out;
    std::ostringstream ss;
    Level log_level;

  public:
    LogLine(Level ll, const char* file_name, int line_number) : log_level(ll)
    {
      ss << "[" << config::to_string(ll) << "]" << file_name << ":"
         << line_number << " - "
         << " - ";
    }

    template <typename T>
    LogLine& operator<<(const T& item)
    {
      ss << item;
      return *this;
    }

    LogLine& operator<<(std::ostream& (*f)(std::ostream&))
    {
      ss << f;
      return *this;
    }
  };

#ifdef INSIDE_ENCLAVE
  struct Out
  {
    bool operator==(LogLine& line)
    {
      if (line.log_level == Level::FATAL)
        throw std::logic_error("Fatal: " + line.ss.str());
      else
        config::writer()->write(config::msg(), line.ss.str());

      return true;
    }
  };
#else
  struct Out
  {
    bool operator==(LogLine& line)
    {
      std::cout << line.ss.str() << std::flush;

      if (line.log_level == Level::FATAL)
        throw std::logic_error("Fatal: " + line.ss.str());

      return true;
    }
  };
#endif

  // The == operator is being used to:
  // 1. Be a lower precedence than <<, such that using << on the LogLine will
  // happen before the LogLine is "equalitied" with the Out.
  // 2. Be a higher precedence than &&, such that the log statement is bound
  // more tightly than the short-circuiting.
  // This allows:
  // LOG_DEBUG << "info" << std::endl;

#define LOG_TRACE \
  logger::config::ok(logger::TRACE) && \
    logger::Out() == logger::LogLine(logger::TRACE, __FILE__, __LINE__)

#define LOG_DEBUG \
  logger::config::ok(logger::DBG) && \
    logger::Out() == logger::LogLine(logger::DBG, __FILE__, __LINE__)

#define LOG_INFO \
  logger::config::ok(logger::INFO) && \
    logger::Out() == logger::LogLine(logger::INFO, __FILE__, __LINE__)

#define LOG_FAIL \
  logger::config::ok(logger::FAIL) && \
    logger::Out() == logger::LogLine(logger::FAIL, __FILE__, __LINE__)

#define LOG_FATAL \
  logger::config::ok(logger::FATAL) && \
    logger::Out() == logger::LogLine(logger::FATAL, __FILE__, __LINE__)
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "logger_formatters.h"
#include "thread_ids.h"

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>

namespace logger
{
  enum Level
  {
#ifdef VERBOSE_LOGGING
    TRACE,
    DEBUG, // events useful for debugging
#endif
    INFO, // important events that should be logged even in release mode
    FAIL, // important failures that should always be logged
    FATAL, // fatal errors that lead to a termination of the program/enclave
    MAX_LOG_LEVEL
  };

  static constexpr Level MOST_VERBOSE = static_cast<Level>(0);

  static constexpr const char* LevelNames[] = {
#ifdef VERBOSE_LOGGING
    "trace",
    "debug",
#endif
    "info",
    "fail",
    "fatal"};

  static const char* to_string(Level l)
  {
    return LevelNames[static_cast<int>(l)];
  }

  static constexpr long int ns_per_s = 1'000'000'000;

  struct LogLine
  {
  public:
    friend struct Out;
    Level log_level;
    std::string file_name;
    size_t line_number;
    uint16_t thread_id;

    std::ostringstream ss;
    std::string msg;

    LogLine(
      Level level,
      const char* file_name,
      size_t line_number,
      std::optional<uint16_t> thread_id_ = std::nullopt) :
      log_level(level),
      file_name(file_name),
      line_number(line_number)
    {
      if (thread_id_.has_value())
      {
        thread_id = *thread_id_;
      }
      else
      {
#ifdef INSIDE_ENCLAVE
        thread_id = threading::get_current_thread_id();
#else
        thread_id = 100;
#endif
      }
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

    void finalize()
    {
      msg = ss.str();
    }
  };

  static std::string get_timestamp(const std::tm& tm, const ::timespec& ts)
  {
    // Sample: "2019-07-19 18:53:25.690267"
    return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:0>6}Z", tm, ts.tv_nsec / 1000);
  }

  class AbstractLogger
  {
  public:
    AbstractLogger() = default;
    virtual ~AbstractLogger() = default;

    virtual void emit(const std::string& s, std::ostream& os = std::cout)
    {
      os << s << std::flush;
    }

    virtual void write(
      const LogLine& ll,
      const std::optional<double>& enclave_offset = std::nullopt) = 0;
  };

#ifndef INSIDE_ENCLAVE
  class JsonConsoleLogger : public AbstractLogger
  {
  public:
    void write(
      const LogLine& ll,
      const std::optional<double>& enclave_offset = std::nullopt) override
    {
      // Fetch time
      ::timespec host_ts;
      ::timespec_get(&host_ts, TIME_UTC);
      std::tm host_tm;
      ::gmtime_r(&host_ts.tv_sec, &host_tm);

      const auto escaped_msg = nlohmann::json(ll.msg).dump();

      std::string s;
      if (enclave_offset.has_value())
      {
        ::timespec enc_ts = host_ts;
        enc_ts.tv_sec += (size_t)enclave_offset.value();
        enc_ts.tv_nsec +=
          (long long)(enclave_offset.value() * ns_per_s) % ns_per_s;

        if (enc_ts.tv_nsec > ns_per_s)
        {
          enc_ts.tv_sec += 1;
          enc_ts.tv_nsec -= ns_per_s;
        }

        std::tm enclave_tm;
        gmtime_r(&enc_ts.tv_sec, &enclave_tm);

        s = fmt::format(
          "{{\"h_ts\":\"{}\",\"e_ts\":\"{}\",\"thread_id\":\"{}\",\"level\":\"{"
          "}\",\"file\":\"{}\","
          "\"number\":\"{}\","
          "\"msg\":{}}}\n",
          get_timestamp(host_tm, host_ts),
          get_timestamp(enclave_tm, enc_ts),
          ll.thread_id,
          to_string(ll.log_level),
          ll.file_name,
          ll.line_number,
          escaped_msg);
      }
      else
      {
        s = fmt::format(
          "{{\"h_ts\":\"{}\",\"thread_id\":\"{}\",\"level\":\"{}\",\"file\":\"{"
          "}"
          "\",\"number\":\"{}\","
          "\"msg\":{}}}\n",
          get_timestamp(host_tm, host_ts),
          ll.thread_id,
          to_string(ll.log_level),
          ll.file_name,
          ll.line_number,
          escaped_msg);
      }

      emit(s);
    }
  };

  static std::string format_to_text(
    const LogLine& ll,
    const std::optional<double>& enclave_offset = std::nullopt)
  {
    // Fetch time
    ::timespec host_ts;
    ::timespec_get(&host_ts, TIME_UTC);
    std::tm host_tm;
    ::gmtime_r(&host_ts.tv_sec, &host_tm);

    auto file_line = fmt::format("{}:{}", ll.file_name, ll.line_number);
    auto file_line_data = file_line.data();

    // Truncate to final characters - if too long, advance char*
    constexpr auto max_len = 36u;

    const auto len = file_line.size();
    if (len > max_len)
      file_line_data += len - max_len;

    if (enclave_offset.has_value())
    {
      // Sample: "2019-07-19 18:53:25.690183 -0.130 " where -0.130 indicates
      // that the time inside the enclave was 130 milliseconds earlier than
      // the host timestamp printed on the line
      return fmt::format(
        "{} {:+01.3f} {:<3} [{:<5}] {:<36} | {}",
        get_timestamp(host_tm, host_ts),
        enclave_offset.value(),
        ll.thread_id,
        to_string(ll.log_level),
        file_line_data,
        ll.msg);
    }
    else
    {
      // Padding on the right to align the rest of the message
      // with lines that contain enclave time offsets
      return fmt::format(
        "{}        {:<3} [{:<5}] {:<36} | {}",
        get_timestamp(host_tm, host_ts),
        ll.thread_id,
        to_string(ll.log_level),
        file_line_data,
        ll.msg);
    }
  }

  class TextConsoleLogger : public AbstractLogger
  {
  public:
    void write(
      const LogLine& ll,
      const std::optional<double>& enclave_offset = std::nullopt) override
    {
      emit(format_to_text(ll, enclave_offset));
    }
  };
#endif

  class config
  {
  public:
    static inline std::vector<std::unique_ptr<AbstractLogger>>& loggers()
    {
      return get_loggers();
    }

#ifndef INSIDE_ENCLAVE
    static inline void add_text_console_logger()
    {
      get_loggers().emplace_back(std::make_unique<TextConsoleLogger>());
    }

    static inline void add_json_console_logger()
    {
      get_loggers().emplace_back(std::make_unique<JsonConsoleLogger>());
    }
#endif

    static inline Level& level()
    {
      static Level the_level = MOST_VERBOSE;

      return the_level;
    }

    static inline bool ok(Level l)
    {
      return l >= level();
    }

  private:
    static inline std::vector<std::unique_ptr<AbstractLogger>>& get_loggers()
    {
      static std::vector<std::unique_ptr<AbstractLogger>> the_loggers;
      return the_loggers;
    }
  };

  struct Out
  {
    bool operator==(LogLine& line)
    {
      line.finalize();

      for (auto const& logger : config::loggers())
      {
        logger->write(line);
      }

#ifndef INSIDE_ENCLAVE
      if (line.log_level == Level::FATAL)
      {
        throw std::logic_error("Fatal: " + format_to_text(line));
      }
#endif

      return true;
    }
  };

  // The == operator is being used to:
  // 1. Be a lower precedence than <<, such that using << on the LogLine will
  // happen before the LogLine is "equalitied" with the Out.
  // 2. Be a higher precedence than &&, such that the log statement is bound
  // more tightly than the short-circuiting.
  // This allows:
  // LOG_DEBUG << "info" << std::endl;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#ifdef VERBOSE_LOGGING
#  define LOG_TRACE \
    logger::config::ok(logger::TRACE) && \
      logger::Out() == logger::LogLine(logger::TRACE, __FILE__, __LINE__)
#  define LOG_TRACE_FMT(s, ...) \
    LOG_TRACE << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl

#  define LOG_DEBUG \
    logger::config::ok(logger::DEBUG) && \
      logger::Out() == logger::LogLine(logger::DEBUG, __FILE__, __LINE__)
#  define LOG_DEBUG_FMT(s, ...) \
    LOG_DEBUG << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl
#else
// Without compile-time VERBOSE_LOGGING option, these logging macros are
// compile-time nops (and cannot be enabled by accident or malice)
#  define LOG_TRACE
#  define LOG_TRACE_FMT(...)

#  define LOG_DEBUG
#  define LOG_DEBUG_FMT(...)
#endif

#define LOG_INFO \
  logger::config::ok(logger::INFO) && \
    logger::Out() == logger::LogLine(logger::INFO, __FILE__, __LINE__)
#define LOG_INFO_FMT(s, ...) \
  LOG_INFO << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl

#define LOG_FAIL \
  logger::config::ok(logger::FAIL) && \
    logger::Out() == logger::LogLine(logger::FAIL, __FILE__, __LINE__)
#define LOG_FAIL_FMT(s, ...) \
  LOG_FAIL << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl

#define LOG_FATAL \
  logger::config::ok(logger::FATAL) && \
    logger::Out() == logger::LogLine(logger::FATAL, __FILE__, __LINE__)
#define LOG_FATAL_FMT(s, ...) \
  LOG_FATAL << fmt::format(FMT_STRING(s), ##__VA_ARGS__) << std::endl

// Convenient wrapper to report exception errors. Exception message is only
// displayed in debug mode
#define LOG_FAIL_EXC(msg) \
  do \
  { \
    LOG_FAIL_FMT("Exception in {}", __PRETTY_FUNCTION__); \
    LOG_DEBUG_FMT("Error: {}", msg); \
  } while (0)

#pragma clang diagnostic pop
}

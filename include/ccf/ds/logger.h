// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/enum_formatter.h"
#include "ccf/ds/logger_level.h"
#include "ccf/threading/thread_ids.h"

#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <type_traits>

namespace ccf::logger
{
  static constexpr LoggerLevel MOST_VERBOSE = LoggerLevel::TRACE;

  static constexpr const char* LevelNames[] = {
    "trace", "debug", "info", "fail", "fatal"};

  static constexpr const char* to_string(LoggerLevel l)
  {
    return LevelNames[static_cast<int>(l)];
  }

  static constexpr long int ns_per_s = 1'000'000'000;

  static constexpr auto preamble_length = 45u;

#ifdef CCF_RAFT_TRACING
  static size_t logical_clock = 0;
#endif

  struct LogLine
  {
  public:
    friend struct Out;
    LoggerLevel log_level;
    std::string tag;
    std::string file_name;
    size_t line_number;
    std::string thread_id;

    std::ostringstream ss;
    std::string msg;

    LogLine(
      LoggerLevel level_,
      std::string_view tag_,
      std::string_view file_name_,
      size_t line_number_) :
      log_level(level_),
      tag(tag_),
      file_name(file_name_),
      line_number(line_number_)
    {
      thread_id = ccf::threading::get_current_thread_name();
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
#ifdef CCF_RAFT_TRACING
    return std::to_string(logical_clock++);
#else
    // Sample: "2019-07-19 18:53:25.690267"
    return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:0>6}Z", tm, ts.tv_nsec / 1000);
#endif
  }

  class AbstractLogger
  {
  public:
    AbstractLogger() = default;
    virtual ~AbstractLogger() = default;

    virtual void emit(const std::string& s)
    {
      std::cout.write(s.c_str(), s.size());
      std::cout.flush();
    }

    virtual void write(
      const LogLine& ll,
      const std::optional<double>& enclave_offset = std::nullopt) = 0;
  };

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

#ifdef CCF_RAFT_TRACING
      auto escaped_msg = ll.msg;
      if (!nlohmann::json::accept(escaped_msg))
      {
        // Only dump to json if not already json, to avoid double-escaping when
        // logging json
        // https://json.nlohmann.me/features/parsing/parse_exceptions/#use-accept-function
        escaped_msg = nlohmann::json(ll.msg).dump();
      }
#else
      const auto escaped_msg = nlohmann::json(ll.msg).dump();
#endif

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
          "}\",\"tag\":\"{}\",\"file\":\"{}\",\"number\":\"{}\",\"msg\":{}}}\n",
          get_timestamp(host_tm, host_ts),
          get_timestamp(enclave_tm, enc_ts),
          ll.thread_id,
          to_string(ll.log_level),
          ll.tag,
          ll.file_name,
          ll.line_number,
          escaped_msg);
      }
      else
      {
        s = fmt::format(
          "{{\"h_ts\":\"{}\",\"thread_id\":\"{}\",\"level\":\"{}\",\"tag\":\"{}"
          "\",\"file\":\"{}\",\"number\":\"{}\",\"msg\":{}}}\n",
          get_timestamp(host_tm, host_ts),
          ll.thread_id,
          to_string(ll.log_level),
          ll.tag,
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

    auto file_line = fmt::format("{}:{} ", ll.file_name, ll.line_number);
    auto file_line_data = file_line.data();

    // The preamble is the level, then tag, then file line. If the file line is
    // too long, the final characters are retained.
    auto preamble = fmt::format(
                      "[{:<5}]{} ",
                      to_string(ll.log_level),
                      (ll.tag.empty() ? "" : fmt::format("[{}]", ll.tag)))
                      .substr(0, preamble_length);
    const auto max_file_line_len = preamble_length - preamble.size();

    const auto len = file_line.size();
    if (len > max_file_line_len)
    {
      file_line_data += len - max_file_line_len;
    }

    preamble += file_line_data;

    if (enclave_offset.has_value())
    {
      // Sample: "2019-07-19 18:53:25.690183 -0.130 " where -0.130 indicates
      // that the time inside the enclave was 130 milliseconds earlier than
      // the host timestamp printed on the line
      return fmt::format(
        "{} {:+01.3f} {:<3} {:<45}| {}\n",
        get_timestamp(host_tm, host_ts),
        enclave_offset.value(),
        ll.thread_id,
        preamble,
        ll.msg);
    }
    else
    {
      // Padding on the right to align the rest of the message
      // with lines that contain enclave time offsets
      return fmt::format(
        "{}        {:<3} {:<45}| {}\n",
        get_timestamp(host_tm, host_ts),
        ll.thread_id,
        preamble,
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

  class config
  {
  public:
    static inline std::vector<std::unique_ptr<AbstractLogger>>& loggers()
    {
      return get_loggers();
    }

    static inline void add_text_console_logger()
    {
      get_loggers().emplace_back(std::make_unique<TextConsoleLogger>());
    }

    static inline void add_json_console_logger()
    {
      get_loggers().emplace_back(std::make_unique<JsonConsoleLogger>());
    }

    static inline void default_init()
    {
      get_loggers().clear();
      add_text_console_logger();
    }

    static inline LoggerLevel& level()
    {
      static LoggerLevel the_level = MOST_VERBOSE;

      return the_level;
    }

    static inline bool ok(LoggerLevel l)
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

      return true;
    }
  };

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

// Clang 12.0 and 13.0 fails to compile the FMT_STRING macro in certain
// contexts. Error is: non-literal type '<dependent type>' cannot be used in a
// constant expression. Since consteval is available in these compilers, format
// should already use compile-time checks.
#if defined(__clang__) && __clang_major__ >= 12
#  define CCF_FMT_STRING(s) (s)
#else
#  define CCF_FMT_STRING(s) FMT_STRING(s)
#endif

// The == operator is being used to:
// 1. Be a lower precedence than <<, such that using << on the LogLine will
// happen before the LogLine is "equalitied" with the Out.
// 2. Be a higher precedence than &&, such that the log statement is bound
// more tightly than the short-circuiting.
// This allows:
// CCF_LOG_OUT(DEBUG, "foo") << "this " << "msg";
#define CCF_LOG_OUT(LVL, TAG) \
  ccf::logger::config::ok(ccf::LoggerLevel::LVL) && \
    ccf::logger::Out() == \
      ccf::logger::LogLine(ccf::LoggerLevel::LVL, TAG, __FILE__, __LINE__)

// To avoid repeating the (s, ...) args for every macro, we cheat with a curried
// macro here by ending the macro with another macro name, which then accepts
// the trailing arguments
#define CCF_LOG_FMT_2(s, ...) fmt::format(CCF_FMT_STRING(s), ##__VA_ARGS__)
#define CCF_LOG_FMT(LVL, TAG) CCF_LOG_OUT(LVL, TAG) << CCF_LOG_FMT_2

  enum class macro
  {
    LOG_TRACE_FMT [[deprecated("Use CCF_APP_TRACE instead")]],
    LOG_DEBUG_FMT [[deprecated("Use CCF_APP_DEBUG instead")]],
    LOG_INFO_FMT [[deprecated("Use CCF_APP_INFO instead")]],
    LOG_FAIL_FMT [[deprecated("Use CCF_APP_FAIL instead")]],
    LOG_FATAL_FMT [[deprecated("Use CCF_APP_FATAL instead")]],
  };

#ifndef CCF_LOGGER_NO_DEPRECATE
#  define CCF_LOGGER_DEPRECATE(MACRO) ccf::logger::macro::MACRO;
#else
#  define CCF_LOGGER_DEPRECATE(MACRO)
#endif

#define LOG_TRACE_FMT CCF_LOGGER_DEPRECATE(LOG_TRACE_FMT) CCF_LOG_FMT(TRACE, "")
#define LOG_DEBUG_FMT CCF_LOGGER_DEPRECATE(LOG_DEBUG_FMT) CCF_LOG_FMT(DEBUG, "")

#define CCF_APP_TRACE CCF_LOG_FMT(TRACE, "app")
#define CCF_APP_DEBUG CCF_LOG_FMT(DEBUG, "app")

#define LOG_INFO_FMT CCF_LOGGER_DEPRECATE(LOG_INFO_FMT) CCF_LOG_FMT(INFO, "")
#define LOG_FAIL_FMT CCF_LOGGER_DEPRECATE(LOG_FAIL_FMT) CCF_LOG_FMT(FAIL, "")
#define LOG_FATAL_FMT CCF_LOGGER_DEPRECATE(LOG_FATAL_FMT) CCF_LOG_FMT(FATAL, "")

#define CCF_APP_INFO CCF_LOG_FMT(INFO, "app")
#define CCF_APP_FAIL CCF_LOG_FMT(FAIL, "app")
#define CCF_APP_FATAL CCF_LOG_FMT(FATAL, "app")

#pragma clang diagnostic pop
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger_level.h"
#include "ccf/threading/thread_ids.h"

#include <algorithm>
#include <array>
#include <ctime>
#include <format>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ccf::logger
{
  static constexpr LoggerLevel MOST_VERBOSE = LoggerLevel::TRACE;

  static constexpr const char* LevelNames[] = {
    "trace", "debug", "info", "fail", "fatal"};

  static constexpr const char* to_string(LoggerLevel l)
  {
    return LevelNames[std::to_underlying(l)];
  }

  static constexpr long int ns_per_s = 1'000'000'000;

  static constexpr auto preamble_length = 45u;

  struct LogLine
  {
  public:
    friend struct Out;
    LoggerLevel log_level;
    std::string tag;
    std::string file_name;
    size_t line_number;
    uint16_t thread_id;

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
      line_number(line_number_),
      thread_id(ccf::threading::get_current_thread_id())
    {}

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
    constexpr size_t nano_per_micro = 1000;
    const auto year = tm.tm_year + 1900LL;
    const auto micros = ts.tv_nsec / nano_per_micro;

    // Keep minimum-width formatting for values outside the fast path.
    if (
      year >= 0 && year <= 9999 && static_cast<unsigned>(tm.tm_mon) < 12 &&
      static_cast<unsigned>(tm.tm_mday) <= 31 &&
      static_cast<unsigned>(tm.tm_hour) < 24 &&
      static_cast<unsigned>(tm.tm_min) < 60 &&
      static_cast<unsigned>(tm.tm_sec) <= 60 && micros <= 999999)
    {
      char timestamp[] = "0000-00-00T00:00:00.000000Z";
      const auto write_digits = [](char* out, size_t width, unsigned value) {
        while (width != 0)
        {
          out[--width] = static_cast<char>('0' + value % 10);
          value /= 10;
        }
      };
      write_digits(timestamp, 4, static_cast<unsigned>(year));
      write_digits(timestamp + 5, 2, static_cast<unsigned>(tm.tm_mon + 1));
      write_digits(timestamp + 8, 2, static_cast<unsigned>(tm.tm_mday));
      write_digits(timestamp + 11, 2, static_cast<unsigned>(tm.tm_hour));
      write_digits(timestamp + 14, 2, static_cast<unsigned>(tm.tm_min));
      write_digits(timestamp + 17, 2, static_cast<unsigned>(tm.tm_sec));
      write_digits(timestamp + 20, 6, static_cast<unsigned>(micros));
      return {timestamp, sizeof(timestamp) - 1};
    }

    return std::format(
      "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
      year,
      tm.tm_mon + 1LL,
      tm.tm_mday,
      tm.tm_hour,
      tm.tm_min,
      tm.tm_sec,
      micros);
  }

  class AbstractLogger
  {
  public:
    AbstractLogger() = default;
    virtual ~AbstractLogger() = default;

    virtual void emit(const std::string& s)
    {
      std::ignore = std::cout.write(s.c_str(), s.size());
      std::cout.flush();
    }

    virtual void write(const LogLine& ll) = 0;
  };

  class JsonConsoleLogger : public AbstractLogger
  {
  public:
    void write(const LogLine& ll) override
    {
      // Fetch time
      ::timespec host_ts{};
      if (::timespec_get(&host_ts, TIME_UTC) == 0)
      {
        throw std::runtime_error("timespec_get failed");
      }
      std::tm host_tm{};
      ::gmtime_r(&host_ts.tv_sec, &host_tm);

      const auto escaped_msg = nlohmann::json(ll.msg).dump();

      std::string s;
      s = std::format(
        "{{\"h_ts\":\"{}\",\"thread_id\":\"{}\",\"level\":\"{}\",\"tag\":\"{}"
        "\",\"file\":\"{}\",\"number\":\"{}\",\"msg\":{}}}\n",
        get_timestamp(host_tm, host_ts),
        ll.thread_id,
        to_string(ll.log_level),
        ll.tag,
        ll.file_name,
        ll.line_number,
        escaped_msg);

      emit(s);
    }
  };

  static std::pair<std::string, size_t> format_text_preamble(const LogLine& ll)
  {
    constexpr size_t level_width = 5;
    const std::string_view level = to_string(ll.log_level);
    std::string preamble = "[";
    preamble += level;
    preamble.append(level_width - level.size(), ' ');
    preamble += ']';
    if (!ll.tag.empty())
    {
      preamble += '[';
      preamble += ll.tag;
      preamble += ']';
    }
    preamble += ' ';
    preamble.resize(std::min<size_t>(preamble.size(), preamble_length));

    auto file_line = ll.file_name;
    file_line += ':';
    file_line += std::to_string(ll.line_number);
    file_line += ' ';
    // Keep the end of the source location when space is limited.
    const auto file_line_size =
      std::min<size_t>(file_line.size(), preamble_length - preamble.size());
    preamble += file_line.c_str() + (file_line.size() - file_line_size);

    auto padded_preamble_size = static_cast<size_t>(preamble_length);
    // Skip the ASCII level prefix, keeping its closing bracket in the
    // measured text so we cut between two printable ASCII characters.
    auto measured = std::string_view(preamble).substr(1 + level_width);
    const auto ascii_suffix = std::find_if_not(
      measured.rbegin(), measured.rend(), [](unsigned char ch) {
        return ch >= ' ' && ch <= '~';
      });
    if (ascii_suffix != measured.rend())
    {
      // Skip the printable ASCII suffix, leaving its first character in
      // place so the width calculation ends at a grapheme boundary.
      const auto suffix_size =
        static_cast<size_t>(ascii_suffix - measured.rbegin());
      measured.remove_suffix(suffix_size == 0 ? 0 : suffix_size - 1);
      const auto skipped = preamble.size() - measured.size();
      padded_preamble_size = skipped +
        std::formatted_size("{:<{}}", measured, preamble_length - skipped);
    }

    const auto padding = padded_preamble_size - preamble.size();
    return {std::move(preamble), padding};
  }

  static std::string format_to_text(const LogLine& ll)
  {
    ::timespec host_ts{};
    if (::timespec_get(&host_ts, TIME_UTC) == 0)
    {
      throw std::runtime_error("timespec_get failed");
    }
    std::tm host_tm{};
    ::gmtime_r(&host_ts.tv_sec, &host_tm);

    const auto [preamble, padding] = format_text_preamble(ll);
    static constexpr auto spaces = [] {
      std::array<char, preamble_length> chars{};
      chars.fill(' ');
      return chars;
    }();
    return std::format(
      "{} {:<3} {}{}| {}\n",
      get_timestamp(host_tm, host_ts),
      ll.thread_id,
      preamble,
      std::string_view(spaces.data(), padding),
      ll.msg);
  }

  class TextConsoleLogger : public AbstractLogger
  {
  public:
    void write(const LogLine& ll) override
    {
      emit(format_to_text(ll));
    }
  };

  class config
  {
  public:
    static std::vector<std::unique_ptr<AbstractLogger>>& loggers()
    {
      return get_loggers();
    }

    static void add_text_console_logger()
    {
      get_loggers().emplace_back(std::make_unique<TextConsoleLogger>());
    }

    static void add_json_console_logger()
    {
      get_loggers().emplace_back(std::make_unique<JsonConsoleLogger>());
    }

    static void default_init()
    {
      get_loggers().clear();
      add_text_console_logger();
    }

    static LoggerLevel& level()
    {
      static LoggerLevel the_level = MOST_VERBOSE;

      return the_level;
    }

    static bool ok(LoggerLevel l)
    {
      return l >= level();
    }

  private:
    static std::vector<std::unique_ptr<AbstractLogger>>& get_loggers()
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

  namespace detail
  {
    template <typename T>
    constexpr const T& format_pattern(const T& pattern)
    {
      return pattern;
    }

    // Keep embedded NULs in string literals rather than treating them as C
    // strings.
    template <size_t N>
    constexpr std::string_view format_pattern(const char (&pattern)[N])
    {
      return {pattern, N - 1};
    }
  }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

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
#define CCF_LOG_FMT_2(s, ...) \
  std::format(ccf::logger::detail::format_pattern(s) __VA_OPT__(, ) __VA_ARGS__)
#define CCF_LOG_FMT(LVL, TAG) CCF_LOG_OUT(LVL, TAG) << CCF_LOG_FMT_2

#define CCF_APP_TRACE CCF_LOG_FMT(TRACE, "app")
#define CCF_APP_DEBUG CCF_LOG_FMT(DEBUG, "app")
#define CCF_APP_INFO CCF_LOG_FMT(INFO, "app")
#define CCF_APP_FAIL CCF_LOG_FMT(FAIL, "app")
#define CCF_APP_FATAL CCF_LOG_FMT(FATAL, "app")

#pragma clang diagnostic pop
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "logger_formatters.h"
#include "ring_buffer.h"
#include "thread_ids.h"

#include <chrono>
#include <cstring>
#include <ctime>
#define FMT_HEADER_ONLY
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <thread>

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

  static constexpr long int ns_per_s = 1'000'000'000;

  class AbstractLogger
  {
  protected:
    std::string log_path;
    std::ofstream f;

  public:
    AbstractLogger() = default;
    AbstractLogger(std::string log_path_) : log_path(log_path_)
    {
      f.open(log_path, std::ios_base::app);
    }
    virtual ~AbstractLogger() = default;

    std::string get_timestamp(const std::tm& tm, const ::timespec& ts)
    {
      // Sample: "2019-07-19 18:53:25.690267"
      return fmt::format("{:%Y-%m-%dT%H:%M:%S}.{:0>6}Z", tm, ts.tv_nsec / 1000);
    }

    virtual std::string format(
      const std::string& file_name,
      size_t line_number,
      const std::string& log_level,
      const std::string& msg,
      const std::tm& host_tm,
      const ::timespec& host_ts,
      uint16_t thread_id,
      const std::optional<float>& enclave_offset = std::nullopt) = 0;

    virtual void write(const std::string& log_line) = 0;

    void dump(const std::string& msg)
    {
      f << msg << std::endl;
    }

    virtual std::ostream& get_stream()
    {
      return f;
    }
  };

  class JsonConsoleLogger : public AbstractLogger
  {
  public:
    std::string format(
      const std::string& file_name,
      size_t line_number,
      const std::string& log_level,
      const std::string& msg,
      const std::tm& host_tm,
      const ::timespec& host_ts,
      uint16_t thread_id,
      const std::optional<float>& enclave_offset = std::nullopt) override
    {
      nlohmann::json j;
      j["m"] = msg;

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

        return fmt::format(
          "{{\"h_ts\":\"{}\",\"e_ts\":\"{}\",\"thread_id\":\"{}\",\"level\":\"{"
          "}\",\"file\":\"{}\","
          "\"number\":\"{}\","
          "\"msg\":{}}}",
          get_timestamp(host_tm, host_ts),
          get_timestamp(enclave_tm, enc_ts),
          thread_id,
          log_level,
          file_name,
          line_number,
          j["m"].dump());
      }

      return fmt::format(
        "{{\"h_ts\":\"{}\",\"thread_id\":\"{}\",\"level\":\"{}\",\"file\":\"{}"
        "\",\"number\":\"{}\","
        "\"msg\":{}}}",
        get_timestamp(host_tm, host_ts),
        thread_id,
        log_level,
        file_name,
        line_number,
        j["m"].dump());
    }

    virtual void write(const std::string& log_line) override
    {
      std::cout << log_line;
    }

    std::ostream& get_stream() override
    {
      return std::cout;
    }
  };

  class ConsoleLogger : public AbstractLogger
  {
  public:
    std::string format(
      const std::string& file_name,
      size_t line_number,
      const std::string& log_level,
      const std::string& msg,
      const std::tm& host_tm,
      const ::timespec& host_ts,
      uint16_t thread_id,
      const std::optional<float>& enclave_offset = std::nullopt) override
    {
      auto file_line = fmt::format("{}:{}", file_name, line_number);
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
          thread_id,
          log_level,
          file_line_data,
          msg);
      }
      else
      {
        // Padding on the right to align the rest of the message
        // with lines that contain enclave time offsets
        return fmt::format(
          "{}        {:<3} [{:<5}] {:<36} | {}",
          get_timestamp(host_tm, host_ts),
          thread_id,
          log_level,
          file_line_data,
          msg);
      }
    }

    void write(const std::string& log_line) override
    {
      std::cout << log_line << std::flush;
    }

    std::ostream& get_stream() override
    {
      return std::cout;
    }
  };

  class config
  {
  public:
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

    static inline std::vector<std::unique_ptr<AbstractLogger>>& loggers()
    {
      std::vector<std::unique_ptr<AbstractLogger>>& the_loggers = get_loggers();
      try_initialize();
      return the_loggers;
    }

    static inline void initialize_with_json_console()
    {
      std::vector<std::unique_ptr<AbstractLogger>>& the_loggers = get_loggers();
      if (the_loggers.size() > 0)
      {
        the_loggers.front() = std::make_unique<JsonConsoleLogger>();
      }
      else
      {
        the_loggers.emplace_back(std::make_unique<JsonConsoleLogger>());
      }
    }

    static inline Level& level()
    {
      static Level the_level = MOST_VERBOSE;

      return the_level;
    }

#ifdef INSIDE_ENCLAVE
    static inline int& msg()
    {
      static int the_msg = ringbuffer::Const::msg_none;
      return the_msg;
    }

    static inline ringbuffer::WriterPtr& writer()
    {
      static ringbuffer::WriterPtr the_writer;
      return the_writer;
    }

    // Current time, as us duration since epoch (from system_clock). Used to
    // produce offsets to host time when logging from inside the enclave
    static std::atomic<std::chrono::microseconds> us;

    static void set_time(std::chrono::microseconds us_)
    {
      us.exchange(us_);
    }

    static std::chrono::microseconds elapsed_us()
    {
      return us;
    }
#endif

    static inline bool ok(Level l)
    {
      return l >= level();
    }

  private:
    static inline void try_initialize()
    {
      std::vector<std::unique_ptr<AbstractLogger>>& the_loggers = get_loggers();
      if (the_loggers.size() == 0)
      {
        the_loggers.emplace_back(std::make_unique<ConsoleLogger>());
      }
    }

    static inline std::vector<std::unique_ptr<AbstractLogger>>& get_loggers()
    {
      static std::vector<std::unique_ptr<AbstractLogger>> the_loggers;
      return the_loggers;
    }
  };

  class LogLine
  {
  private:
    friend struct Out;
    std::ostringstream ss;
    Level log_level;
    std::string file_name;
    size_t line_number;
    std::string ll_str;
    std::string msg;
    uint16_t thread_id;

  public:
    LogLine(Level ll, const char* file_name, size_t line_number) :
      log_level(ll),
      file_name(file_name),
      line_number(line_number),
#ifdef INSIDE_ENCLAVE
      thread_id(threading::get_current_thread_id())
#else
      thread_id(100)
#endif
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

#ifdef INSIDE_ENCLAVE
  struct Out
  {
    bool operator==(LogLine& line)
    {
      line.finalize();
      config::writer()->write(
        config::msg(),
        config::elapsed_us().count(),
        line.file_name,
        line.line_number,
        line.log_level,
        line.thread_id,
        line.msg);

      return true;
    }
  };
#else
  struct Out
  {
    bool operator==(LogLine& line)
    {
      line.finalize();
      write(
        line.file_name,
        line.line_number,
        line.log_level,
        line.thread_id,
        line.msg);

      return true;
    }

    static void write(
      const std::string& file_name,
      size_t line_number,
      const Level& log_level,
      uint16_t thread_id,
      const std::string& msg)
    {
      // When logging from host code, print local time.
      ::timespec ts;
      ::timespec_get(&ts, TIME_UTC);
      std::tm now;
      ::gmtime_r(&ts.tv_sec, &now);

      for (auto const& logger : config::loggers())
      {
        logger->write(logger->format(
          file_name,
          line_number,
          config::to_string(log_level),
          msg,
          now,
          ts,
          thread_id));
      }

      if (log_level == Level::FATAL)
      {
        throw std::logic_error(
          "Fatal: " +
          config::loggers().front()->format(
            file_name,
            line_number,
            config::to_string(log_level),
            msg,
            now,
            ts,
            thread_id));
      }
    }

    static void write(
      const std::string& file_name,
      size_t line_number,
      const Level& log_level,
      uint16_t thread_id,
      const std::string& msg,
      size_t enclave_time_us)
    {
      // When logging messages received from the enclave, print local time,
      // and the offset to time inside the enclave at the time the message
      // was logged there.
      // Not thread-safe (uses std::localtime)
      ::timespec ts;
      ::timespec_get(&ts, TIME_UTC);
      std::tm now;
      ::gmtime_r(&ts.tv_sec, &now);

      // Represent offset as a real (counting seconds) to handle both small
      // negative _and_ positive numbers. Since the system clock used is not
      // monotonic, the offset we calculate could go in either direction, and tm
      // can't represent small negative values.
      std::optional<double> offset_time = std::nullopt;

      // If enclave doesn't know the
      // current time yet, don't try to produce an offset, just give them the
      // host's time (producing offset of 0)
      if (enclave_time_us != 0)
      {
        // Enclave time is recomputed every time. If multiple threads
        // log inside the enclave, offsets may not always increase
        const double enclave_time_s = enclave_time_us / 1'000'000.0;
        const double host_time_s = ts.tv_sec + (ts.tv_nsec / (double)ns_per_s);

        offset_time = enclave_time_s - host_time_s;
      }

      for (auto const& logger : config::loggers())
      {
        logger->write(logger->format(
          file_name,
          line_number,
          config::to_string(log_level),
          msg,
          now,
          ts,
          thread_id,
          offset_time));
      }

      if (log_level == Level::FATAL)
      {
        throw std::logic_error(
          "Fatal: " +
          config::loggers().front()->format(
            file_name,
            line_number,
            config::to_string(log_level),
            msg,
            now,
            ts,
            thread_id,
            offset_time));
      }
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
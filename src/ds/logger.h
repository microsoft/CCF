// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ring_buffer.h"

#include <chrono>
#include <cstring>
#include <ctime>
#include <fmt/format_header_only.h>
#include <fmt/time.h>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <sstream>
#include <string>
#include <thread>

extern std::map<std::thread::id, uint16_t> thread_ids;

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

  static constexpr size_t ns_per_s = 1'000'000'000;

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
      const std::optional<::timespec>& enclave_ts = std::nullopt) = 0;

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

  class JsonLogger : public AbstractLogger
  {
  public:
    JsonLogger(std::string log_path) : AbstractLogger(log_path) {}

    std::string format(
      const std::string& file_name,
      size_t line_number,
      const std::string& log_level,
      const std::string& msg,
      const std::tm& host_tm,
      const ::timespec& host_ts,
      uint16_t thread_id,
      const std::optional<::timespec>& enclave_ts = std::nullopt) override
    {
      nlohmann::json j;
      j["m"] = msg;

      if (enclave_ts.has_value())
      {
        std::tm enclave_tm;
        auto enc_ts = enclave_ts.value();
        ::timespec_get(&enc_ts, TIME_UTC);
        ::gmtime_r(&enc_ts.tv_sec, &enclave_tm);

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

    void write(const std::string& log_line) override
    {
      dump(log_line);
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
      const std::optional<::timespec>& enclave_ts = std::nullopt) override
    {
      auto file_line = fmt::format("{}:{}", file_name, line_number);
      auto file_line_data = file_line.data();

      // Truncate to final characters - if too long, advance char*
      constexpr auto max_len = 36u;

      const auto len = file_line.size();
      if (len > max_len)
        file_line_data += len - max_len;

      if (enclave_ts.has_value())
      {
        // Sample: "2019-07-19 18:53:25.690183 -0.130 " where -0.130 indicates
        // that the time inside the enclave was 130 milliseconds earlier than
        // the host timestamp printed on the line
        return fmt::format(
          "{} -{}.{:0>3} {:<3} [{:<5}] {:<36} | {}",
          get_timestamp(host_tm, host_ts),
          enclave_ts.value().tv_sec,
          enclave_ts.value().tv_nsec / 1000000,
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

    static inline std::vector<std::unique_ptr<AbstractLogger>>& loggers()
    {
      static std::vector<std::unique_ptr<AbstractLogger>> the_loggers;
      static bool initialized = false;
      if (!initialized)
      {
        initialized = true;
        the_loggers.emplace_back(std::make_unique<ConsoleLogger>());
      }
      return the_loggers;
    }

    static inline Level& level()
    {
      static Level the_level =
#ifdef VERBOSE_LOGGING
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

    static inline ringbuffer::WriterPtr& writer()
    {
      static ringbuffer::WriterPtr the_writer;
      return the_writer;
    }

    // Count of milliseconds elapsed since enclave started, used to produce
    // offsets to host time when logging from inside the enclave
    static std::atomic<std::chrono::milliseconds> ms;

    static void tick(std::chrono::milliseconds ms_)
    {
      ms.exchange(ms.load() + ms_);
    }

    static std::chrono::milliseconds elapsed_ms()
    {
      return ms;
    }
#else
    // Timestamp of first tick. Used by the host when receiving log messages
    // from the enclave. Combined with the elapsed ms reported by the enclave,
    // and used to compute the offset between time inside the enclave, and time
    // on the host when the log message is received.
    static ::timespec start;

    static void set_start(
      const std::chrono::time_point<std::chrono::system_clock>& start_)
    {
      start.tv_sec = std::chrono::time_point_cast<std::chrono::seconds>(start_)
                       .time_since_epoch()
                       .count();
      start.tv_nsec =
        std::chrono::time_point_cast<std::chrono::nanoseconds>(start_)
          .time_since_epoch()
          .count() -
        start.tv_sec * ns_per_s;
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
    std::string file_name;
    size_t line_number;
    std::string ll_str;
    std::string msg;
    uint16_t thread_id;

  public:
    LogLine(Level ll, const char* file_name, size_t line_number) :
      file_name(file_name),
      line_number(line_number),
      log_level(ll),
#ifdef INSIDE_ENCLAVE
      thread_id(thread_ids[std::this_thread::get_id()])
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
        config::elapsed_ms(),
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
    }

    static void write(
      const std::string& file_name,
      size_t line_number,
      const Level& log_level,
      uint16_t thread_id,
      const std::string& msg,
      size_t ms_offset_from_start)
    {
      // When logging messages received from the enclave, print local time,
      // and the offset to time inside the enclave at the time the message
      // was logged there.
      // Not thread-safe (uses std::localtime)
      ::timespec ts;
      ::timespec_get(&ts, TIME_UTC);
      std::tm now;
      ::gmtime_r(&ts.tv_sec, &now);
      time_t elapsed_s = ms_offset_from_start / 1000;
      ssize_t elapsed_ns = (ms_offset_from_start % 1000) * 1000000;

      // Enclave time is recomputed every time. If multiple threads
      // log inside the enclave, offsets may not always increase
      ::timespec enclave_ts{logger::config::start.tv_sec + elapsed_s,
                            logger::config::start.tv_nsec + elapsed_ns};

      if (enclave_ts.tv_nsec > ns_per_s)
      {
        enclave_ts.tv_sec++;
        enclave_ts.tv_nsec -= ns_per_s;
      }

      // We assume time in the enclave is behind (less than) time on the host.
      // This would reliably be the case if we used a monotonic clock,
      // but we want human-readable wall-clock time. Inaccurate offsets may
      // occasionally occur as a result.
      enclave_ts.tv_sec = ts.tv_sec - enclave_ts.tv_sec;
      enclave_ts.tv_nsec = ts.tv_nsec - enclave_ts.tv_nsec;
      if (enclave_ts.tv_nsec < 0)
      {
        enclave_ts.tv_sec--;
        enclave_ts.tv_nsec += ns_per_s;
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
          enclave_ts));
      }

      if (log_level == Level::FATAL)
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
            enclave_ts));
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
#define LOG_TRACE_FMT(...) LOG_TRACE << fmt::format(__VA_ARGS__) << std::endl

#define LOG_DEBUG \
  logger::config::ok(logger::DBG) && \
    logger::Out() == logger::LogLine(logger::DBG, __FILE__, __LINE__)
#define LOG_DEBUG_FMT(...) LOG_DEBUG << fmt::format(__VA_ARGS__) << std::endl

#define LOG_INFO \
  logger::config::ok(logger::INFO) && \
    logger::Out() == logger::LogLine(logger::INFO, __FILE__, __LINE__)
#define LOG_INFO_FMT(...) LOG_INFO << fmt::format(__VA_ARGS__) << std::endl

#define LOG_FAIL \
  logger::config::ok(logger::FAIL) && \
    logger::Out() == logger::LogLine(logger::FAIL, __FILE__, __LINE__)
#define LOG_FAIL_FMT(...) LOG_FAIL << fmt::format(__VA_ARGS__) << std::endl

#define LOG_FATAL \
  logger::config::ok(logger::FATAL) && \
    logger::Out() == logger::LogLine(logger::FATAL, __FILE__, __LINE__)
#define LOG_FATAL_FMT(...) LOG_FATAL << fmt::format(__VA_ARGS__) << std::endl
}
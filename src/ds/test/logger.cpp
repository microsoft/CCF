// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/join.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ds/internal_logger.h"
#include "ds/time_bound_logger.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <doctest/doctest.h>
#include <format>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

TEST_CASE("Joined ranges preserve element formatting")
{
  const std::vector<uint8_t> bytes{0, 9, 16, 127, 128, 255};
  CHECK(
    std::format("[{}]", ccf::ds::join(bytes, ", ")) ==
    "[0, 9, 16, 127, 128, 255]");
  CHECK(
    std::format("{:02x}", ccf::ds::join(bytes, " ")) == "00 09 10 7f 80 ff");
  CHECK(
    std::format("{:02X}", ccf::ds::join(bytes.rbegin(), bytes.rend(), "")) ==
    "FF807F100900");
  CHECK(
    std::format(
      "{}",
      ccf::ds::join(
        std::counted_iterator(bytes.begin(), 2), std::default_sentinel, ",")) ==
    "0,9");
  CHECK(std::format("{}", ccf::ds::join(std::array<int, 0>{}, ",")).empty());
  CHECK(std::format("{}", ccf::ds::join(std::array{42}, ",")) == "42");
  CHECK(
    std::format("{}", ccf::ds::join(std::array{1, 2, 3}, ", ")) == "1, 2, 3");
  CHECK(
    std::format("{:>3}", ccf::ds::join(std::array{1, 20}, "|")) == "  1| 20");
  CHECK(
    std::format("{:0{}}", ccf::ds::join(std::array{1, 20}, "|"), 3) ==
    "001|020");
  CHECK(std::format("{}", ccf::ds::join(std::array{"a", "b"}, "/")) == "a/b");
  const std::map<int, int> values{{1, 10}, {2, 20}};
  CHECK(
    std::format("{}", ccf::ds::join(std::views::keys(values), ",")) == "1,2");
  CHECK(
    std::format(
      "{}",
      ccf::ds::join(
        std::views::iota(1, 5) |
          std::views::filter([](int value) { return value % 2 == 0; }),
        ", ")) == "2, 4");

  const auto range = ccf::ds::join(bytes, "");
  CHECK_THROWS_AS(
    (void)std::vformat("{:s}", std::make_format_args(range)),
    std::format_error);
  CHECK_THROWS_AS(
    (void)std::vformat("{", std::make_format_args(range)), std::format_error);
}

TEST_CASE("UTC timestamps retain their precision and calendar range")
{
  std::tm calendar{};
  calendar.tm_year = 2024 - 1900;
  calendar.tm_mon = 1;
  calendar.tm_mday = 29;
  calendar.tm_hour = 12;
  calendar.tm_min = 34;
  calendar.tm_sec = 56;
  const timespec time{0, 123456789};
  CHECK(
    ccf::logger::get_timestamp(calendar, time) ==
    "2024-02-29T12:34:56.123456Z");
  CHECK(
    ccf::logger::get_timestamp(calendar, timespec{0, 999}) ==
    "2024-02-29T12:34:56.000000Z");
  CHECK(ccf::ds::to_x509_time_string(calendar) == "20240229123456Z");

  for (const auto* input :
       {"19500101000000Z", "19700101000000Z", "99991231235959Z"})
  {
    CHECK(
      ccf::ds::to_x509_time_string(ccf::ds::time_point_from_string(input)) ==
      input);
  }
  CHECK(
    ccf::ds::to_x509_time_string(std::chrono::system_clock::time_point{}) ==
    "19700101000000Z");
  CHECK(
    ccf::ds::to_x509_time_string(
      std::chrono::system_clock::time_point{} -
      std::chrono::milliseconds(1500)) == "19691231235959Z");
  CHECK(
    ccf::ds::to_x509_time_string(
      std::chrono::system_clock::time_point{} -
      std::chrono::milliseconds(500)) == "19700101000000Z");
  CHECK_THROWS_AS(
    ccf::ds::to_x509_time_string(ccf::nonstd::SystemClock::time_point::max()),
    std::runtime_error);

  std::tm far_future{};
  far_future.tm_year = std::numeric_limits<int>::max();
  far_future.tm_mday = 1;
  CHECK(
    ccf::logger::get_timestamp(far_future, timespec{}) ==
    "2147485547-01-01T00:00:00.000000Z");
  CHECK(ccf::ds::to_x509_time_string(far_future) == "21474855470101000000Z");
}

TEST_CASE("Logger timestamp preserves padding at year boundaries")
{
  std::tm calendar{};
  calendar.tm_mday = 1;
  calendar.tm_sec = 60;
  const timespec time{0, 1999};

  calendar.tm_year = -1901;
  CHECK(
    ccf::logger::get_timestamp(calendar, time) ==
    "-001-01-01T00:00:60.000001Z");
  calendar.tm_year = -1900;
  CHECK(
    ccf::logger::get_timestamp(calendar, time) ==
    "0000-01-01T00:00:60.000001Z");
  calendar.tm_year = 9999 - 1900;
  CHECK(
    ccf::logger::get_timestamp(calendar, time) ==
    "9999-01-01T00:00:60.000001Z");
  calendar.tm_year = 10000 - 1900;
  CHECK(
    ccf::logger::get_timestamp(calendar, time) ==
    "10000-01-01T00:00:60.000001Z");
}

TEST_CASE("Disabled logging does not evaluate format arguments")
{
  const auto previous_level = ccf::logger::config::level();
  ccf::logger::config::level() = ccf::LoggerLevel::FATAL;
  size_t evaluated = 0;
  CCF_APP_INFO("{}", ++evaluated);
  LOG_DEBUG_FMT("{}", ++evaluated);
  CHECK(evaluated == 0);
  ccf::logger::config::level() = previous_level;
}

TEST_CASE("Thread IDs are provided by the logger headers")
{
  ccf::threading::reset_thread_id_generator();
  ccf::threading::set_current_thread_id(ccf::threading::MAIN_THREAD_ID);

  REQUIRE(
    ccf::threading::get_current_thread_id() == ccf::threading::MAIN_THREAD_ID);

  ccf::threading::set_current_thread_id(42);
  REQUIRE(ccf::threading::get_current_thread_id() == 42);

  ccf::threading::reset_thread_id_generator(7);
  ccf::threading::ThreadID thread_id = ccf::threading::invalid_thread_id;
  std::thread t(
    [&thread_id] { thread_id = ccf::threading::get_current_thread_id(); });
  t.join();
  REQUIRE(thread_id == 7);

  ccf::threading::reset_thread_id_generator();
  ccf::threading::set_current_thread_id(ccf::threading::MAIN_THREAD_ID);
}

template <typename Base>
class TestLogger : public Base
{
public:
  std::vector<std::string>& logs;

  TestLogger(std::vector<std::string>& l) : logs(l) {}

  void emit(const std::string& s) override
  {
    logs.push_back(s);
  }
};

using TestTextLogger = TestLogger<ccf::logger::TextConsoleLogger>;
using TestJsonLogger = TestLogger<ccf::logger::JsonConsoleLogger>;

TEST_CASE("JSON logs retain wall-clock timestamps and string messages")
{
  std::vector<std::string> logs;
  TestJsonLogger logger(logs);
  ccf::logger::LogLine line(ccf::LoggerLevel::INFO, "test", __FILE__, __LINE__);
  line.msg = R"({"function":"replicate"})";
  logger.write(line);

  REQUIRE(logs.size() == 1);
  const auto record = nlohmann::json::parse(logs.front());
  CHECK(record["msg"] == line.msg);
  const auto timestamp = record["h_ts"].get<std::string>();
  REQUIRE(timestamp.size() == 27);
  CHECK(timestamp[10] == 'T');
  CHECK(timestamp.back() == 'Z');
}

class ScopedLoggerConfig
{
  const ccf::LoggerLevel previous_level = ccf::logger::config::level();
  const std::chrono::microseconds previous_default_max_time =
    ccf::ds::TimeBoundLogger::default_max_time;
  std::vector<std::unique_ptr<ccf::logger::AbstractLogger>> previous_loggers;

public:
  ScopedLoggerConfig() :
    previous_loggers(std::exchange(ccf::logger::config::loggers(), {}))
  {}

  ScopedLoggerConfig(const ScopedLoggerConfig&) = delete;
  ScopedLoggerConfig& operator=(const ScopedLoggerConfig&) = delete;

  ~ScopedLoggerConfig()
  {
    ccf::logger::config::loggers() = std::move(previous_loggers);
    ccf::logger::config::level() = previous_level;
    ccf::ds::TimeBoundLogger::default_max_time = previous_default_max_time;
  }
};

class ScopedCerrCapture
{
  std::ostringstream captured;
  std::streambuf* previous = std::cerr.rdbuf(captured.rdbuf());

public:
  ScopedCerrCapture() = default;
  ScopedCerrCapture(const ScopedCerrCapture&) = delete;
  ScopedCerrCapture& operator=(const ScopedCerrCapture&) = delete;

  ~ScopedCerrCapture()
  {
    std::cerr.rdbuf(previous);
  }

  std::string str() const
  {
    return captured.str();
  }
};

class ScopedCoutCapture
{
  std::ostringstream captured;
  std::streambuf* previous = std::cout.rdbuf(captured.rdbuf());

public:
  ScopedCoutCapture() = default;
  ScopedCoutCapture(const ScopedCoutCapture&) = delete;
  ScopedCoutCapture& operator=(const ScopedCoutCapture&) = delete;

  ~ScopedCoutCapture()
  {
    std::cout.rdbuf(previous);
  }

  void clear()
  {
    captured.str("");
    captured.clear();
  }

  std::string str() const
  {
    return captured.str();
  }
};

#ifndef CCF_CFT_TRACING
TEST_CASE("Logger timestamp retains microsecond precision")
{
  std::tm tm{};
  tm.tm_year = 126;
  tm.tm_mon = 5;
  tm.tm_mday = 16;
  tm.tm_hour = 5;
  tm.tm_min = 30;
  tm.tm_sec = 6;
  ::timespec ts{};

  CHECK(ccf::logger::get_timestamp(tm, ts) == "2026-06-16T05:30:06.000000Z");
  ts.tv_nsec = 123456789;
  CHECK(ccf::logger::get_timestamp(tm, ts) == "2026-06-16T05:30:06.123456Z");
  ts.tv_nsec = 999999999;
  CHECK(ccf::logger::get_timestamp(tm, ts) == "2026-06-16T05:30:06.999999Z");
}
#endif

TEST_CASE("Application log formatting preserves text and JSON messages")
{
  using namespace std::string_literals;

  std::vector<std::string> text_logs;
  std::vector<std::string> json_logs;
  const ScopedLoggerConfig restore_config;
  ccf::logger::config::level() = ccf::LoggerLevel::INFO;
  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestTextLogger>(text_logs));
  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestJsonLogger>(json_logs));

  const std::vector<uint8_t> bytes = {0, 1, 127, 255};
  CCF_APP_INFO(
    "value={:.2f} hex={:02x} enum={} optional={}",
    1.25,
    ccf::ds::join(bytes, ""),
    std::to_underlying(ccf::LoggerLevel::INFO),
    std::optional{7}.value());
  CCF_APP_INFO("escaped={{}}\n{}\0{}", "before", "after");

  const std::vector<std::string> expected = {
    "value=1.25 hex=00017fff enum=2 optional=7", "escaped={}\nbefore\0after"s};
  REQUIRE(text_logs.size() == expected.size());
  REQUIRE(json_logs.size() == expected.size());
  for (size_t i = 0; i < expected.size(); ++i)
  {
    CHECK(text_logs[i].ends_with(expected[i] + "\n"));
    CHECK(nlohmann::json::parse(json_logs[i]).at("msg") == expected[i]);
  }
}

TEST_CASE("Time-bound logger duration formatting")
{
  using ccf::ds::TimeBoundLogger;
  using namespace std::chrono_literals;

  CHECK(TimeBoundLogger::human_time(0us) == "  0.000us");
  CHECK(TimeBoundLogger::human_time(999us) == "999.000us");
  CHECK(TimeBoundLogger::human_time(1000us) == "  1.000ms");
  CHECK(TimeBoundLogger::human_time(999999us) == "999.999ms");
  CHECK(TimeBoundLogger::human_time(1s) == "  1.000s");
}

TEST_CASE("Time-bound logger captures the configured default")
{
  using ccf::ds::TimeBoundLogger;
  using namespace std::chrono_literals;

  const ScopedLoggerConfig restore_config;
  TimeBoundLogger::default_max_time = 1s;
  TimeBoundLogger first("first");
  TimeBoundLogger::default_max_time = 2s;
  TimeBoundLogger second("second");
  TimeBoundLogger explicit_threshold("explicit", 3s);

  CHECK(first.max_time == 1s);
  CHECK(second.max_time == 2s);
  CHECK(explicit_threshold.max_time == 3s);
}

TEST_CASE("Time-bound logger reports slow operations at the expected level")
{
  using ccf::ds::TimeBoundLogger;
  using namespace std::chrono_literals;

  std::vector<std::string> logs;
  const ScopedLoggerConfig restore_config;
  ccf::logger::config::level() = ccf::LoggerLevel::INFO;
  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestTextLogger>(logs));

  {
    TimeBoundLogger timer("fast", 1h);
    timer.start_time -= 30min;
  }
  {
    TimeBoundLogger timer("slow", 1h);
    timer.start_time -= 2h;
  }
  {
    TimeBoundLogger timer("very slow", 1h);
    timer.start_time -= 200h;
  }

  REQUIRE(logs.size() == 2);
  CHECK(logs[0].contains("info"));
  CHECK(logs[0].contains("): slow"));
  CHECK(logs[1].contains("fail"));
  CHECK(logs[1].contains("): very slow"));
}

TEST_CASE("Framework logging macros")
{
  std::vector<std::string> logs;

  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestTextLogger>(logs));

  {
    REQUIRE(logs.empty());
    LOG_INFO_FMT("Hello A");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("info"));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Hello A"));

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    LOG_FAIL_FMT("Hello B");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("fail"));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Hello B"));

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    LOG_FATAL_FMT("Hello C");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("fatal"));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Hello C"));

    logs.clear();
  }

  ccf::logger::config::loggers().clear();
}

TEST_CASE("Only explicit fatal diagnostics write to stderr")
{
  const ScopedLoggerConfig restore_config;
  ccf::logger::config::level() = ccf::LoggerLevel::TRACE;
  ScopedCoutCapture captured_out;
  ScopedCerrCapture captured_err;

  const auto check_console_logger = [&](auto logger) {
    auto& loggers = ccf::logger::config::loggers();
    loggers.clear();
    loggers.emplace_back(std::move(logger));
    captured_out.clear();

    LOG_INFO_FMT("Recoverable information");
    LOG_FAIL_FMT("Recoverable failure");
    LOG_FATAL_FMT("Fatal severity label without termination");

    CHECK(captured_err.str().empty());
    const auto output = captured_out.str();
    CHECK(output.contains("Recoverable information"));
    CHECK(output.contains("Recoverable failure"));
    CHECK(output.contains("Fatal severity label without termination"));
  };

  check_console_logger(std::make_unique<ccf::logger::TextConsoleLogger>());
  check_console_logger(std::make_unique<ccf::logger::JsonConsoleLogger>());
  captured_out.clear();
  ccf::logger::write_fatal_diagnostic("Node terminated");
  CHECK(captured_out.str().empty());
  CHECK(captured_err.str() == "Fatal error: Node terminated\n");
}

TEST_CASE("Application logging macros")
{
  std::vector<std::string> logs;

  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestTextLogger>(logs));

  {
    REQUIRE(logs.empty());
    CCF_APP_INFO("Hello A");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("info"));
    REQUIRE(log.contains("[app]"));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Hello A"));

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    CCF_APP_FAIL("Hello B");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("fail"));
    REQUIRE(log.contains("[app]"));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Hello B"));

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    CCF_APP_FATAL("Hello C");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("fatal"));
    REQUIRE(log.contains("[app]"));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Hello C"));

    logs.clear();
  }

  ccf::logger::config::loggers().clear();
}

constexpr auto custom_tag = "my tag";
#define CUSTOM_LOG CCF_LOG_FMT(INFO, custom_tag)

constexpr auto custom_long_tag =
  "A very long tag that may need to be truncated";
#define CUSTOM_LOG_LONG CCF_LOG_FMT(INFO, custom_long_tag)

TEST_CASE("Text logger preserves padding, truncation and message bytes")
{
  using namespace std::string_literals;

  const auto check = [](
                       uint16_t thread,
                       std::string_view tag,
                       std::string_view filename,
                       std::string_view expected_preamble) {
    ccf::logger::LogLine line(ccf::LoggerLevel::INFO, tag, filename, 123);
    line.thread_id = thread;
    line.msg = "before\0\xe7\x95\x8c after\n"s;

    const auto text = ccf::logger::format_to_text(line);
    const auto timestamp_end = text.find(' ');
    REQUIRE(timestamp_end != std::string::npos);
    CHECK(
      text.substr(timestamp_end) ==
      std::format(" {:<3} {:<45}| {}\n", thread, expected_preamble, line.msg));
  };

  check(7, "", "file.cpp", "[info ] file.cpp:123 ");
  check(65535, "app", "file.cpp", "[info ][app] file.cpp:123 ");
  check(
    123, "", std::string(33, 'x'), "[info ] " + std::string(32, 'x') + ":123 ");
  check(0, std::string(40, 'x'), "file.cpp", "[info ][" + std::string(37, 'x'));
}

TEST_CASE("Custom logging macros")
{
  std::vector<std::string> logs;

  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestTextLogger>(logs));

  {
    REQUIRE(logs.empty());
    CUSTOM_LOG("Some message");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("info"));
    REQUIRE(log.contains(custom_tag));
    REQUIRE(log.contains("logger.cpp"));
    REQUIRE(log.contains("Some message"));

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    CUSTOM_LOG_LONG("Some other message");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.contains("info"));
    // Search for smaller prefixes of the long tag, expect that one is
    // eventually present
    std::string truncated_tag = custom_long_tag;
    while (truncated_tag.size() > 0)
    {
      if (log.contains(truncated_tag))
      {
        break;
      }
      truncated_tag.resize(truncated_tag.size() - 1);
    }
    REQUIRE(truncated_tag.size() > 0);
    REQUIRE(log.contains("Some other message"));

    logs.clear();
  }

  ccf::logger::config::loggers().clear();
}
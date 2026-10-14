// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "ds/time_bound_logger.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <cstdint>
#include <ctime>
#include <doctest/doctest.h>
#include <memory>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

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

#ifndef CCF_RAFT_TRACING
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
    fmt::join(bytes, ""),
    ccf::LoggerLevel::INFO,
    std::optional{7});
  CCF_APP_INFO("escaped={{}}\n{}\0{}", "before", "after");

  const std::vector<std::string> expected = {
    "value=1.25 hex=00017fff enum=2 optional=optional(7)",
    "escaped={}\nbefore\0after"s};
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
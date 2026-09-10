// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h"
#include "ds/time_bound_logger.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <doctest/doctest.h>
#include <memory>
#include <stdexcept>
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

TEST_CASE("Logger test configuration is restored during stack unwinding")
{
  using ccf::ds::TimeBoundLogger;
  using namespace std::chrono_literals;

  std::vector<std::string> logs;
  const ScopedLoggerConfig restore_original_config;
  TimeBoundLogger::default_max_time = 42s;
  ccf::logger::config::level() = ccf::LoggerLevel::DEBUG;
  ccf::logger::config::loggers().emplace_back(
    std::make_unique<TestTextLogger>(logs));
  const auto* previous_logger = ccf::logger::config::loggers().front().get();

  auto change_config_then_throw = [&logs]() {
    const ScopedLoggerConfig restore_config;
    TimeBoundLogger::default_max_time = 1s;
    ccf::logger::config::level() = ccf::LoggerLevel::INFO;
    ccf::logger::config::loggers().emplace_back(
      std::make_unique<TestTextLogger>(logs));
    throw std::runtime_error("Unwind logger configuration");
  };
  CHECK_THROWS_AS(change_config_then_throw(), std::runtime_error);

  CHECK(TimeBoundLogger::default_max_time == 42s);
  CHECK(ccf::logger::config::level() == ccf::LoggerLevel::DEBUG);
  REQUIRE(ccf::logger::config::loggers().size() == 1);
  CHECK(ccf::logger::config::loggers().front().get() == previous_logger);
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
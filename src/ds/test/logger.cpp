// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/ds/join.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ds/internal_logger.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <array>
#include <doctest/doctest.h>
#include <limits>
#include <ranges>
#include <thread>

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
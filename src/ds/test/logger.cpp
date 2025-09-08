// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ds/internal_logger.h.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

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
    REQUIRE(log.find("info") != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Hello A") != std::string::npos);

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    LOG_FAIL_FMT("Hello B");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.find("fail") != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Hello B") != std::string::npos);

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    LOG_FATAL_FMT("Hello C");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.find("fatal") != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Hello C") != std::string::npos);

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
    REQUIRE(log.find("info") != std::string::npos);
    REQUIRE(log.find("[app]") != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Hello A") != std::string::npos);

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    CCF_APP_FAIL("Hello B");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.find("fail") != std::string::npos);
    REQUIRE(log.find("[app]") != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Hello B") != std::string::npos);

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    CCF_APP_FATAL("Hello C");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.find("fatal") != std::string::npos);
    REQUIRE(log.find("[app]") != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Hello C") != std::string::npos);

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
    REQUIRE(log.find("info") != std::string::npos);
    REQUIRE(log.find(custom_tag) != std::string::npos);
    REQUIRE(log.find("logger.cpp") != std::string::npos);
    REQUIRE(log.find("Some message") != std::string::npos);

    logs.clear();
  }

  {
    REQUIRE(logs.empty());
    CUSTOM_LOG_LONG("Some other message");
    REQUIRE(logs.size() == 1);

    const auto& log = logs[0];
    REQUIRE(log.find("info") != std::string::npos);
    // Search for smaller prefixes of the long tag, expect that one is
    // eventually present
    std::string truncated_tag = custom_long_tag;
    while (truncated_tag.size() > 0)
    {
      const auto search = log.find(truncated_tag);
      if (search != std::string::npos)
      {
        break;
      }
      truncated_tag.resize(truncated_tag.size() - 1);
    }
    REQUIRE(truncated_tag.size() > 0);
    REQUIRE(log.find("Some other message") != std::string::npos);

    logs.clear();
  }

  ccf::logger::config::loggers().clear();
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/internal_logger.h.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <fstream>
#include <nlohmann/json.hpp>

TEST_CASE("Test custom log format")
{
  std::string test_log_file = "./test_json_logger.txt";
  remove(test_log_file.c_str());
  ccf::logger::config::add_json_console_logger();
  ccf::logger::config::level() = ccf::LoggerLevel::DEBUG;
  std::string log_msg_dbg = "log_msg_dbg";
  std::string log_msg_trace = "log_msg_trace";

  std::ofstream out(test_log_file.c_str());
  std::streambuf* coutbuf = std::cout.rdbuf();
  std::cout.rdbuf(out.rdbuf());

  LOG_DEBUG_FMT("{}", log_msg_dbg);
  LOG_TRACE_FMT("{}", log_msg_trace);
  LOG_DEBUG_FMT("{}", log_msg_dbg);
  LOG_TRACE_FMT("{}", log_msg_trace);
  LOG_DEBUG_FMT("{}", log_msg_dbg);

  out.flush();
  out.close();

  std::cout.rdbuf(coutbuf);

  std::ifstream f(test_log_file);
  std::string line;
  size_t line_count = 0;
  while (std::getline(f, line))
  {
    line_count++;
    auto j = nlohmann::json::parse(line);
    auto host_ts = j.find("h_ts");
    REQUIRE(host_ts != j.end());
    REQUIRE(j["msg"] == log_msg_dbg);
    REQUIRE(j["file"] == __FILE__);
    auto line_number = j.find("number");
    REQUIRE(line_number != j.end());
    REQUIRE(j["level"] == "debug");
  }
  REQUIRE(line_count == 3);
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../httpserver.h"

#include <doctest/doctest.h>
#include <string>
#include <queue>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

std::vector<uint8_t> post(const std::string& body)
{
  auto req = fmt::format(
    "POST / HTTP/1.1\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: {}\r\n\r\n{}",
    body.size(), body
  );
  return std::vector<uint8_t>(req.begin(), req.end());
}

std::queue<std::string> chunks;

int on_req(http_parser * parser, const char * at, size_t length)
{
  //std::cout << "Parsed: " << std::string(at, length) << std::endl;
  chunks.emplace(at, length);
  return 0;
}

TEST_CASE("Complete request")
{
  std::string r("{}");
  enclave::http::Parser p(on_req, nullptr);
  auto req = post(r);
  auto parsed = p.execute(req.data(), req.size());
  CHECK(parsed == req.size());
  CHECK(chunks.size() == 1);
  CHECK(chunks.front() == "{}");
  chunks.pop();
}

TEST_CASE("Partial request")
{
  std::string r("{}");
  enclave::http::Parser p(on_req, nullptr);
  auto req = post(r);
  size_t offset = 10;
  auto parsed = p.execute(req.data(), req.size() - offset);
  CHECK(parsed == req.size() - offset);

  parsed = p.execute(req.data() + req.size() - offset, offset);
  CHECK(parsed == offset);

  CHECK(chunks.size() == 1);
  CHECK(chunks.front() == r);
  chunks.pop();
}

TEST_CASE("Partial body")
{
  std::string r("{\"a_json_key\": \"a_json_value\"}");
  enclave::http::Parser p(on_req, nullptr);
  auto req = post(r);
  size_t offset = 10;
  auto parsed = p.execute(req.data(), req.size() - offset);
  CHECK(parsed == req.size() - offset);

  parsed = p.execute(req.data() + req.size() - offset, offset);
  CHECK(parsed == offset);

  CHECK(chunks.size() == 2);
  CHECK(chunks.front() == "{\"a_json_key\": \"a_js");
  chunks.pop();
  CHECK(chunks.front() == "on_value\"}");
  chunks.pop();
}
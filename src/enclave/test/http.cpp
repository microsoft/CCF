// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../http.h"

#include "../http_builder.h"

#include <doctest/doctest.h>
#include <queue>
#include <string>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

class StubProc : public enclave::http::MsgProcessor
{
public:
  struct Msg
  {
    http_method method;
    std::string path;
    std::string query;
    std::vector<uint8_t> body;
  };

  std::queue<Msg> received;

  virtual void msg(
    http_method method,
    const std::string& path,
    const std::string& query,
    std::vector<uint8_t> body) override
  {
    received.emplace(Msg{method, path, query, body});
  }
};

constexpr auto request_0 = "{\"a_json_key\": \"a_json_value\"}";
constexpr auto request_1 = "{\"another_json_key\": \"another_json_value\"}";

std::vector<uint8_t> s_to_v(char const* s)
{
  const auto d = (const uint8_t*)s;
  return std::vector<uint8_t>(d, d + strlen(s));
}

using namespace enclave::http;

TEST_CASE("Complete request")
{
  std::vector<uint8_t> r;

  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  auto req = build_post_request(r);
  auto parsed = p.execute(req.data(), req.size());

  CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  CHECK(m.method == HTTP_POST);
  CHECK(m.body == r);
}

TEST_CASE("Parsing error")
{
  std::vector<uint8_t> r;

  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  auto req = build_post_request(r);
  req[6] = '\n';
  CHECK_THROWS_WITH(
    p.execute(req.data(), req.size()),
    "HTTP parsing failed: HPE_INVALID_HEADER_TOKEN: invalid character in "
    "header");

  CHECK(sp.received.empty());
}

TEST_CASE("Partial request")
{
  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = build_post_request(r0);
  size_t offset = 10;

  auto parsed = p.execute(req.data(), req.size() - offset);
  CHECK(parsed == req.size() - offset);
  parsed = p.execute(req.data() + req.size() - offset, offset);
  CHECK(parsed == offset);

  CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  CHECK(m.method == HTTP_POST);
  CHECK(m.body == r0);
}

TEST_CASE("Partial body")
{
  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = build_post_request(r0);
  size_t offset = build_post_header(r0).size() + 4;

  auto parsed = p.execute(req.data(), req.size() - offset);
  CHECK(parsed == req.size() - offset);
  parsed = p.execute(req.data() + req.size() - offset, offset);
  CHECK(parsed == offset);

  CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  CHECK(m.method == HTTP_POST);
  CHECK(m.body == r0);
}

TEST_CASE("Multiple requests")
{
  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = build_post_request(r0);
  const auto r1 = s_to_v(request_1);
  auto req1 = build_post_request(r1);
  std::copy(req1.begin(), req1.end(), std::back_inserter(req));

  auto parsed = p.execute(req.data(), req.size());
  CHECK(parsed == req.size());

  {
    CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    CHECK(m.method == HTTP_POST);
    CHECK(m.body == r0);
  }

  sp.received.pop();

  {
    CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    CHECK(m.method == HTTP_POST);
    CHECK(m.body == r1);
  }
}

TEST_CASE("Method parsing")
{
  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  bool choice = false;
  for (const auto method : {HTTP_DELETE, HTTP_GET, HTTP_POST, HTTP_PUT})
  {
    const auto r = s_to_v(choice ? request_0 : request_1);
    auto req = build_request(method, r);
    auto parsed = p.execute(req.data(), req.size());

    CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    CHECK(m.method == method);
    CHECK(m.body == r);

    sp.received.pop();
    choice = !choice;
  }
}

TEST_CASE("URL parsing")
{
  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  const auto path = "/foo/123";

  Request r;
  r.set_path(path);
  r.set_query_param("balance", "42");
  r.set_query_param("id", "100");

  const auto body = s_to_v(request_0);
  auto req = r.build_request(body);

  auto parsed = p.execute(req.data(), req.size());
  CHECK(parsed == req.size());

  CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  CHECK(m.method == HTTP_POST);
  CHECK(m.body == body);
  CHECK(m.path == path);
  CHECK(m.query.find("balance=42") != std::string::npos);
  CHECK(m.query.find("id=100") != std::string::npos);
  CHECK(m.query.find("&") != std::string::npos);
}

TEST_CASE("Pessimal transport")
{
  StubProc sp;
  enclave::http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = build_post_request(r0);

  size_t done = 0;
  while (done < req.size())
  {
    // Simulate dreadful transport - send between 1 and 8 bytes at a time
    size_t next = (rand() % 8) + 1;
    next = std::min(next, req.size() - done);
    auto parsed = p.execute(req.data() + done, next);
    CHECK(parsed == next);
    done += next;
  }

  CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  CHECK(m.method == HTTP_POST);
  CHECK(m.body == r0);
}
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

// TEST_CASE("Partial body")
// {
//   StubProc sp;
//   enclave::http::Parser p(HTTP_REQUEST, sp);

//   auto req = build_post_request(request_0);
//   size_t offset = 10;

//   auto parsed = p.execute(req.data(), req.size() - offset);
//   CHECK(parsed == req.size() - offset);

//   parsed = p.execute(req.data() + req.size() - offset, offset);
//   CHECK(parsed == offset);

//   sp.expect({request_0});
// }

// TEST_CASE("Multiple requests")
// {
//   StubProc sp;
//   enclave::http::Parser p(HTTP_REQUEST, sp);

//   auto req = post(request_0);
//   auto req1 = post(request_1);
//   std::copy(req1.begin(), req1.end(), std::back_inserter(req));

//   auto parsed = p.execute(req.data(), req.size());
//   CHECK(parsed == req.size());

//   sp.expect({request_0, request_1});
// }

// TEST_CASE("URL parsing")
// {
//   StubProc sp;
//   enclave::http::Parser p(HTTP_REQUEST, sp);

//   const auto path = "/foo/123";
//   const auto query = "balance=42&id=100";
//   auto req = post(request_0, path, query);

//   auto parsed = p.execute(req.data(), req.size());
//   CHECK(parsed == req.size());

//   sp.expect({request_0});
//   CHECK(sp.path == path);
//   CHECK(sp.query == query);
// }

// TEST_CASE("Pessimal transport")
// {
//   StubProc sp;
//   enclave::http::Parser p(HTTP_REQUEST, sp);

//   auto req = post(request_0);
//   auto req1 = post(request_1);
//   std::copy(req1.begin(), req1.end(), std::back_inserter(req));

//   auto parsed = p.execute(req.data(), req.size());
//   CHECK(parsed == req.size());

//   sp.expect({request_0, request_1});
// }
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../http_builder.h"
#include "../http_parser.h"

#include <doctest/doctest.h>
#include <queue>
#include <string>
#define FMT_HEADER_ONLY
#include <fmt/format.h>

constexpr auto request_0 = "{\"a_json_key\": \"a_json_value\"}";
constexpr auto request_1 = "{\"another_json_key\": \"another_json_value\"}";

std::vector<uint8_t> s_to_v(char const* s)
{
  const auto d = (const uint8_t*)s;
  return std::vector<uint8_t>(d, d + strlen(s));
}

std::string to_lowercase(std::string s)
{
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return std::tolower(c);
  });
  return s;
}

TEST_CASE("Complete request")
{
  std::vector<uint8_t> r;

  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  auto req = http::build_post_request(r);
  auto parsed = p.execute(req.data(), req.size());

  CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  CHECK(m.method == HTTP_POST);
  CHECK(m.body == r);
}

TEST_CASE("Parsing error")
{
  std::vector<uint8_t> r;

  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  auto req = http::build_post_request(r);
  req[6] = '\n';

  bool threw_with = false;
  try
  {
    p.execute(req.data(), req.size());
  }
  catch (std::exception& e)
  {
    threw_with = strstr(e.what(), "HPE_INVALID_HEADER_TOKEN") != nullptr;
  }

  CHECK(threw_with);
  CHECK(sp.received.empty());
}

TEST_CASE("Partial request")
{
  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
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
  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
  size_t offset = http::build_post_header(r0).size() + 4;

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
  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
  const auto r1 = s_to_v(request_1);
  auto req1 = http::build_post_request(r1);
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
  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  bool choice = false;
  for (const auto method : {HTTP_DELETE, HTTP_GET, HTTP_POST, HTTP_PUT})
  {
    const auto r = s_to_v(choice ? request_0 : request_1);
    auto req = http::build_request(method, r);
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
  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  const auto path = "/foo/123";

  http::Request r(path);
  r.set_query_param("balance", "42");
  r.set_query_param("id", "100");

  const auto body = s_to_v(request_0);
  r.set_body(&body);
  auto req = r.build_request();

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
  const http::HeaderMap h1 = {{"foo", "bar"}, {"baz", "42"}};
  const http::HeaderMap h2 = {{"foo", "barbar"},
                              {"content-type", "application/json"},
                              {"x-custom-header", "custom user data"},
                              {"x-MixedCASE", "DontCARE"}};

  http::SimpleMsgProcessor sp;
  http::Parser p(HTTP_REQUEST, sp);

  // Use the same processor and test repeatedly to make sure headers are for
  // only the current request
  for (const auto& headers : {{}, h1, h2, h1, h2, h2, h1})
  {
    auto builder =
      http::Request("/path/which/will/be/spliced/during/transport", HTTP_POST);
    for (const auto& it : headers)
    {
      builder.set_header(it.first, it.second);
    }

    const auto r0 = s_to_v(request_0);
    builder.set_body(&r0);
    auto req = builder.build_request();

    size_t done = 0;
    while (done < req.size())
    {
      // Simulate dreadful transport - send 1 byte at a time
      size_t next = 1;
      next = std::min(next, req.size() - done);
      auto parsed = p.execute(req.data() + done, next);
      CHECK(parsed == next);
      done += next;
    }

    CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    CHECK(m.method == HTTP_POST);
    CHECK(m.body == r0);

    // Check each specified header is present and matches. May include other
    // auto-inserted headers - these are ignored
    for (const auto& it : headers)
    {
      const auto found = m.headers.find(to_lowercase(it.first));
      CHECK(found != m.headers.end());
      CHECK(found->second == it.second);
    }

    sp.received.pop();
  }
}
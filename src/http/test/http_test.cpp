// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
#include "../http_builder.h"
#include "../http_parser.h"
#include "../http_sig.h"
#include "tls/key_pair.h"

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

DOCTEST_TEST_CASE("Complete request")
{
  for (const auto method : {HTTP_POST, HTTP_GET, HTTP_DELETE})
  {
    const std::vector<uint8_t> r = {0, 1, 2, 3};
    constexpr auto url = "/some/path/to/a/resource";

    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp);

    auto request = http::Request(url, method);
    request.set_body(&r);
    auto req = request.build_request();
    auto parsed = p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == method);
    DOCTEST_CHECK(m.path == url);
    DOCTEST_CHECK(m.body == r);
  }
}

DOCTEST_TEST_CASE("Complete response")
{
  for (const auto status : {HTTP_STATUS_OK,
                            HTTP_STATUS_BAD_REQUEST,
                            HTTP_STATUS_INTERNAL_SERVER_ERROR})
  {
    const std::vector<uint8_t> r = {0, 1, 2, 3};

    http::SimpleResponseProcessor sp;
    http::ResponseParser p(sp);

    auto response = http::Response(status);
    response.set_body(&r);
    auto res = response.build_response();
    auto parsed = p.execute(res.data(), res.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.status == status);
    DOCTEST_CHECK(m.body == r);
  }
}

DOCTEST_TEST_CASE("Parsing error")
{
  std::vector<uint8_t> r;

  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

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

  DOCTEST_CHECK(threw_with);
  DOCTEST_CHECK(sp.received.empty());
}

DOCTEST_TEST_CASE("Partial request")
{
  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
  size_t offset = 10;

  auto parsed = p.execute(req.data(), req.size() - offset);
  DOCTEST_CHECK(parsed == req.size() - offset);
  parsed = p.execute(req.data() + req.size() - offset, offset);
  DOCTEST_CHECK(parsed == offset);

  DOCTEST_CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  DOCTEST_CHECK(m.method == HTTP_POST);
  DOCTEST_CHECK(m.body == r0);
}

DOCTEST_TEST_CASE("Partial body")
{
  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
  size_t offset = http::build_post_header(r0).size() + 4;

  auto parsed = p.execute(req.data(), req.size() - offset);
  DOCTEST_CHECK(parsed == req.size() - offset);
  parsed = p.execute(req.data() + req.size() - offset, offset);
  DOCTEST_CHECK(parsed == offset);

  DOCTEST_CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  DOCTEST_CHECK(m.method == HTTP_POST);
  DOCTEST_CHECK(m.body == r0);
}

DOCTEST_TEST_CASE("Multiple requests")
{
  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
  const auto r1 = s_to_v(request_1);
  auto req1 = http::build_post_request(r1);
  std::copy(req1.begin(), req1.end(), std::back_inserter(req));

  auto parsed = p.execute(req.data(), req.size());
  DOCTEST_CHECK(parsed == req.size());

  {
    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_POST);
    DOCTEST_CHECK(m.body == r0);
  }

  sp.received.pop();

  {
    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_POST);
    DOCTEST_CHECK(m.body == r1);
  }
}

DOCTEST_TEST_CASE("Method parsing")
{
  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

  bool choice = false;
  for (const auto method : {HTTP_DELETE, HTTP_GET, HTTP_POST, HTTP_PUT})
  {
    const auto r = s_to_v(choice ? request_0 : request_1);
    auto req = http::build_request(method, r);
    auto parsed = p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == method);
    DOCTEST_CHECK(m.body == r);

    sp.received.pop();
    choice = !choice;
  }
}

DOCTEST_TEST_CASE("URL parsing")
{
  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

  const auto path = "/foo/123";

  http::Request r(path);
  r.set_query_param("balance", "42");
  r.set_query_param("id", "100");

  const auto body = s_to_v(request_0);
  r.set_body(&body);
  auto req = r.build_request();

  auto parsed = p.execute(req.data(), req.size());
  DOCTEST_CHECK(parsed == req.size());

  DOCTEST_CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  DOCTEST_CHECK(m.method == HTTP_POST);
  DOCTEST_CHECK(m.body == body);
  DOCTEST_CHECK(m.path == path);
  DOCTEST_CHECK(m.query.find("balance=42") != std::string::npos);
  DOCTEST_CHECK(m.query.find("id=100") != std::string::npos);
  DOCTEST_CHECK(m.query.find("&") != std::string::npos);
}

DOCTEST_TEST_CASE("Pessimal transport")
{
  logger::config::level() = logger::INFO;

  const http::HeaderMap h1 = {{"foo", "bar"}, {"baz", "42"}};
  const http::HeaderMap h2 = {{"foo", "barbar"},
                              {"content-type", "application/json"},
                              {"x-custom-header", "custom user data"},
                              {"x-MixedCASE", "DontCARE"}};

  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

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
      DOCTEST_CHECK(parsed == next);
      done += next;
    }

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_POST);
    DOCTEST_CHECK(m.body == r0);

    // Check each specified header is present and matches. May include other
    // auto-inserted headers - these are ignored
    for (const auto& it : headers)
    {
      const auto found = m.headers.find(to_lowercase(it.first));
      DOCTEST_CHECK(found != m.headers.end());
      DOCTEST_CHECK(found->second == it.second);
    }

    sp.received.pop();
  }
}

DOCTEST_TEST_CASE("Escaping")
{
  {
    const std::string unescaped =
      "This has many@many+many \\% \" AWKWARD :;-=?!& ++ characters %20%20";
    const std::string escaped =
      "This+has+many%40many%2Bmany+%5C%25+%22+AWKWARD+%3A%3B-%3D%3F%21%26+%2B%"
      "2b+"
      "characters+%2520%2520";

    std::string s = http::url_decode(escaped);
    DOCTEST_REQUIRE(s == unescaped);
  }

  {
    const std::string request =
      "GET /foo/bar?this=that&awkward=escaped+string+%3A%3B-%3D%3F%21%22 "
      "HTTP/1.1\r\n\r\n";

    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp);

    const std::vector<uint8_t> req(request.begin(), request.end());
    auto parsed = p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_GET);
    DOCTEST_CHECK(m.path == "/foo/bar");
    DOCTEST_CHECK(m.query == "this=that&awkward=escaped string :;-=?!\"");
  }

  {
    const std::string request =
      "GET "
      "/hello%20world?hello%20world=hello%20world&saluton%20mondo=saluton%"
      "20mondo HTTP/1.1\r\n\r\n";

    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp);

    const std::vector<uint8_t> req(request.begin(), request.end());
    auto parsed = p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_GET);
    DOCTEST_CHECK(m.path == "/hello%20world");
    DOCTEST_CHECK(
      m.query == "hello world=hello world&saluton mondo=saluton mondo");
  }
}

struct SignedRequestProcessor : public http::SimpleRequestProcessor
{
  std::queue<ccf::SignedReq> signed_reqs;

  virtual void handle_request(
    http_method method,
    const std::string_view& path,
    const std::string& query,
    http::HeaderMap&& headers,
    std::vector<uint8_t>&& body) override
  {
    const auto signed_req = http::HttpSignatureVerifier::parse(
      http_method_str(method), path, query, headers, body);
    DOCTEST_REQUIRE(signed_req.has_value());

    signed_reqs.push(signed_req.value());

    http::SimpleRequestProcessor::handle_request(
      method, path, query, std::move(headers), std::move(body));
  }
};

DOCTEST_TEST_CASE("Signatures")
{
  // Produce signed requests with some formatting variations, ensure we can
  // parse them
  auto kp = tls::make_key_pair();

  http::Request request("/foo", HTTP_POST);
  request.set_query_param("param", "value");
  request.set_query_param("pet", "dog");
  request.set_header("Host", "example.com");
  request.set_header("Date", "Sun, 05 Jan 2014 21:31:40 GMT");
  request.set_header("Content-Type", "application/json");

  const std::string body_s("{\"hello\": \"world\"}");
  const std::vector<uint8_t> body_v(body_s.begin(), body_s.end());

  request.set_body(body_v.data(), body_v.size());

  http::add_digest_header(request);

  {
    const auto& headers = request.get_headers();
    const auto it = headers.find(http::headers::DIGEST);
    DOCTEST_REQUIRE(it != headers.end());

    constexpr auto expected_digest_value =
      "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=";
    DOCTEST_REQUIRE(it->second == expected_digest_value);
  }

  DOCTEST_SUBCASE("Some headers")
  {
    std::vector<std::string_view> headers_to_sign;
    headers_to_sign.emplace_back(http::auth::SIGN_HEADER_REQUEST_TARGET);
    headers_to_sign.emplace_back(http::headers::DIGEST);

    http::sign_request(request, kp, headers_to_sign);

    const auto serial_request = request.build_request();

    SignedRequestProcessor sp;
    http::RequestParser p(sp);

    auto parsed = p.execute(serial_request.data(), serial_request.size());
    DOCTEST_REQUIRE(parsed == serial_request.size());
    DOCTEST_REQUIRE(!sp.signed_reqs.empty());
  }

  DOCTEST_SUBCASE("All headers")
  {
    std::vector<std::string_view> headers_to_sign;
    headers_to_sign.emplace_back(http::auth::SIGN_HEADER_REQUEST_TARGET);
    for (const auto& header_it : request.get_headers())
    {
      headers_to_sign.emplace_back(header_it.first);
    }

    // Try all permutations to test order-independence
    std::sort(headers_to_sign.begin(), headers_to_sign.end());
    while (true)
    {
      http::sign_request(request, kp, headers_to_sign);

      const auto serial_request = request.build_request();

      SignedRequestProcessor sp;
      http::RequestParser p(sp);

      auto parsed = p.execute(serial_request.data(), serial_request.size());
      DOCTEST_REQUIRE(parsed == serial_request.size());
      DOCTEST_REQUIRE(sp.signed_reqs.size() == 1);

      sp.signed_reqs.pop();

      const bool was_last_permutation =
        !std::next_permutation(headers_to_sign.begin(), headers_to_sign.end());
      if (was_last_permutation)
      {
        break;
      }
    }
  }

  DOCTEST_SUBCASE("Unquoted auth values")
  {
    std::vector<std::string_view> headers_to_sign;
    headers_to_sign.emplace_back(http::auth::SIGN_HEADER_REQUEST_TARGET);
    for (const auto& header_it : request.get_headers())
    {
      headers_to_sign.emplace_back(header_it.first);
    }

    http::sign_request(request, kp, headers_to_sign);

    const auto& headers = request.get_headers();
    const auto auth_it = headers.find(http::headers::AUTHORIZATION);
    DOCTEST_REQUIRE(auth_it != headers.end());

    std::string auth_value = auth_it->second;
    const auto new_end = std::remove(auth_value.begin(), auth_value.end(), '"');
    auth_value.erase(new_end, auth_value.end());

    request.set_header(http::headers::AUTHORIZATION, auth_value);

    const auto serial_request = request.build_request();

    SignedRequestProcessor sp;
    http::RequestParser p(sp);

    auto parsed = p.execute(serial_request.data(), serial_request.size());
    DOCTEST_REQUIRE(parsed == serial_request.size());
    DOCTEST_REQUIRE(sp.signed_reqs.size() == 1);
  }
}
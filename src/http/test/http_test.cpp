// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/http_accept.h"
#include "ccf/http_query.h"
#include "crypto/openssl/ec_public_key.h"
#include "http/http_builder.h"
#include "http/http_digest.h"
#include "http/http_parser.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define DOCTEST_CONFIG_NO_SHORT_MACRO_NAMES
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
  ccf::nonstd::to_lower(s);
  return s;
}

// Production parsing rejects conflicting Content-Length and Transfer-Encoding
// headers. These test-only parsers exercise llhttp's chunked precedence path.
class LenientChunkedLengthRequestParser : public http::RequestParser
{
public:
  LenientChunkedLengthRequestParser(
    http::RequestProcessor& proc,
    const ccf::http::ParserConfiguration& config) :
    http::RequestParser(proc, config)
  {
    llhttp_set_lenient_chunked_length(&parser, 1);
  }
};

class LenientChunkedLengthResponseParser : public http::ResponseParser
{
public:
  explicit LenientChunkedLengthResponseParser(http::ResponseProcessor& proc) :
    http::ResponseParser(proc)
  {
    llhttp_set_lenient_chunked_length(&parser, 1);
  }
};

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
    p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == method);
    DOCTEST_CHECK(m.url == url);
    DOCTEST_CHECK(m.body == r);
  }
}

DOCTEST_TEST_CASE("Complete response")
{
  for (const auto status :
       {HTTP_STATUS_OK,
        HTTP_STATUS_BAD_REQUEST,
        HTTP_STATUS_INTERNAL_SERVER_ERROR})
  {
    const std::vector<uint8_t> r = {0, 1, 2, 3};

    ::http::SimpleResponseProcessor sp;
    ::http::ResponseParser p(sp);

    auto response = ::http::Response(status);
    response.set_body(&r);
    auto res = response.build_response();
    p.execute(res.data(), res.size());

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

DOCTEST_TEST_CASE("Parsing fuzzing")
{
  std::vector<uint8_t> r;

#define ADD_HTTP_METHOD(NUM, NAME, STRING) HTTP_##NAME,
  std::vector<llhttp_method> all_methods{HTTP_ALL_METHOD_MAP(ADD_HTTP_METHOD)};
#undef ADD_HTTP_METHOD

  for (auto method : all_methods)
  {
    const auto orig_req = http::build_request(method, r);

    std::vector<char> replacements = {'\0', '\1'};
    for (auto i : {0, 1, 2})
    {
      for (auto c : replacements)
      {
        auto req = orig_req;
        req[i] = c;

        http::SimpleRequestProcessor sp;
        http::RequestParser p(sp);
        DOCTEST_CHECK_THROWS(p.execute(req.data(), req.size()));
        DOCTEST_CHECK(sp.received.empty());
      }
    }
  }
}

DOCTEST_TEST_CASE("Partial request")
{
  http::SimpleRequestProcessor sp;
  http::RequestParser p(sp);

  const auto r0 = s_to_v(request_0);
  auto req = http::build_post_request(r0);
  size_t offset = 10;

  p.execute(req.data(), req.size() - offset);
  p.execute(req.data() + req.size() - offset, offset);

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
  size_t offset = http::build_post_header(r0).size() + r0.size() / 3;

  p.execute(req.data(), req.size() - offset);
  p.execute(req.data() + req.size() - offset, offset);

  DOCTEST_CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  DOCTEST_CHECK(m.method == HTTP_POST);
  DOCTEST_CHECK(m.body == r0);
}

DOCTEST_TEST_CASE("Body too large")
{
  ccf::http::ParserConfiguration config;
  config.max_body_size = ccf::ds::SizeString("8B");

  // Response parsing uses the same base Parser, so an oversized Content-Length
  // should also be rejected at headers-complete time.
  {
    ::http::SimpleResponseProcessor sp;
    ::http::ResponseParser p(sp);

    const auto too_big = ccf::http::default_max_body_size.count_bytes() + 1;
    const auto res =
      fmt::format("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", too_big);
    const auto bytes = std::vector<uint8_t>(res.begin(), res.end());

    DOCTEST_CHECK_THROWS_AS(
      p.execute(bytes.data(), bytes.size()),
      http::RequestPayloadTooLargeException);
    DOCTEST_CHECK(sp.received.empty());
  }

  // A body exceeding max_body_size is rejected. With a Content-Length header
  // the parser exits early, at the point where headers are complete, before
  // any body chunk has been appended.
  {
    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp, config);

    const std::vector<uint8_t> body(16, 'a');
    auto req = http::build_post_request(body);

    DOCTEST_CHECK_THROWS_AS(
      p.execute(req.data(), req.size()), http::RequestPayloadTooLargeException);
    DOCTEST_CHECK(sp.received.empty());
  }

  // The early exit happens before any body bytes are received. Send only the
  // headers (advertising a large Content-Length) with no body at all, and the
  // request is still rejected.
  {
    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp, config);

    const std::vector<uint8_t> body(16, 'a');
    auto header = http::build_post_header(body);

    DOCTEST_CHECK_THROWS_AS(
      p.execute(header.data(), header.size()),
      http::RequestPayloadTooLargeException);
    DOCTEST_CHECK(sp.received.empty());
  }

  // A body within max_body_size is accepted.
  {
    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp, config);

    const std::vector<uint8_t> body(4, 'a');
    auto req = http::build_post_request(body);

    p.execute(req.data(), req.size());
    DOCTEST_CHECK(!sp.received.empty());
    DOCTEST_CHECK(sp.received.front().body == body);
  }

  // A body exactly at max_body_size is accepted: the check is strictly
  // greater-than, so the boundary value is allowed.
  {
    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp, config);

    const std::vector<uint8_t> body(8, 'a');
    auto req = http::build_post_request(body);

    p.execute(req.data(), req.size());
    DOCTEST_CHECK(!sp.received.empty());
    DOCTEST_CHECK(sp.received.front().body == body);
  }

  // The append_body accumulation check is the fallback that rejects chunked
  // messages once the chunks received exceed max_body_size.
  auto build_chunked_message = [](
                                 std::string_view start_line,
                                 size_t body_size,
                                 std::string_view additional_headers = {}) {
    const std::string chunk(body_size, 'a');
    const std::string message = fmt::format(
      "{}\r\n"
      "transfer-encoding: chunked\r\n"
      "{}"
      "\r\n"
      "{:x}\r\n"
      "{}\r\n"
      "0\r\n"
      "\r\n",
      start_line,
      additional_headers,
      body_size,
      chunk);
    return std::vector<uint8_t>(message.begin(), message.end());
  };

  // An oversized chunked body is rejected by append_body as the chunks
  // accumulate, even though no Content-Length was advertised.
  {
    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp, config);

    auto req = build_chunked_message("POST / HTTP/1.1", 16);

    DOCTEST_CHECK_THROWS_AS(
      p.execute(req.data(), req.size()), http::RequestPayloadTooLargeException);
    DOCTEST_CHECK(sp.received.empty());
  }

  // A chunked body within max_body_size is accepted.
  {
    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp, config);

    auto req = build_chunked_message("POST / HTTP/1.1", 4);

    p.execute(req.data(), req.size());
    DOCTEST_CHECK(!sp.received.empty());
    DOCTEST_CHECK(sp.received.front().body.size() == 4);
  }

  // When llhttp accepts both headers, Transfer-Encoding takes precedence and
  // the ignored Content-Length must not trigger the early size check.
  {
    http::SimpleRequestProcessor sp;
    LenientChunkedLengthRequestParser p(sp, config);

    auto req =
      build_chunked_message("POST / HTTP/1.1", 4, "content-length: 16\r\n");

    p.execute(req.data(), req.size());
    DOCTEST_CHECK(!sp.received.empty());
    DOCTEST_CHECK(sp.received.front().body.size() == 4);
  }

  // Ignoring Content-Length for a chunked message does not bypass the limit:
  // append_body still rejects the actual accumulated body size.
  {
    http::SimpleRequestProcessor sp;
    LenientChunkedLengthRequestParser p(sp, config);

    auto req =
      build_chunked_message("POST / HTTP/1.1", 16, "content-length: 4\r\n");

    DOCTEST_CHECK_THROWS_AS(
      p.execute(req.data(), req.size()), http::RequestPayloadTooLargeException);
    DOCTEST_CHECK(sp.received.empty());
  }

  // The same chunked precedence applies to responses in the shared Parser.
  {
    ::http::SimpleResponseProcessor sp;
    LenientChunkedLengthResponseParser p(sp);

    const auto too_big = ccf::http::default_max_body_size.count_bytes() + 1;
    const auto content_length = fmt::format("content-length: {}\r\n", too_big);
    auto response = build_chunked_message("HTTP/1.1 200 OK", 4, content_length);

    p.execute(response.data(), response.size());
    DOCTEST_CHECK(!sp.received.empty());
    DOCTEST_CHECK(sp.received.front().body.size() == 4);
  }
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

  DOCTEST_SUBCASE("All at once")
  {
    p.execute(req.data(), req.size());
  }

  DOCTEST_SUBCASE("In chunks")
  {
    constexpr auto chunks = 7;
    const auto chunk_size = req.size() / chunks;
    auto remaining = req.size();
    auto next_data = req.data();

    while (remaining > 0)
    {
      const auto next = std::min(remaining, chunk_size);
      p.execute(next_data, next);
      next_data += next;
      remaining -= next;
    }
  }

  DOCTEST_SUBCASE("Byte-by-byte")
  {
    constexpr size_t next = 1;
    for (size_t i = 0; i < req.size(); ++i)
    {
      p.execute(req.data() + i, next);
    }
  }

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
    p.execute(req.data(), req.size());

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

  p.execute(req.data(), req.size());

  DOCTEST_CHECK(!sp.received.empty());
  const auto& m = sp.received.front();
  DOCTEST_CHECK(m.method == HTTP_POST);
  DOCTEST_CHECK(m.body == body);
  std::string path_, query_, fragment_;
  std::tie(path_, query_, fragment_) = http::split_url_path(m.url);
  DOCTEST_CHECK(path_ == path);
  DOCTEST_CHECK(query_.find("balance=42") != std::string::npos);
  DOCTEST_CHECK(query_.find("id=100") != std::string::npos);
  DOCTEST_CHECK(query_.find("&") != std::string::npos);
}

DOCTEST_TEST_CASE("Pessimal transport")
{
  ccf::logger::config::level() = ccf::LoggerLevel::INFO;

  const ccf::http::HeaderMap h1 = {{"foo", "bar"}, {"baz", "42"}};
  const ccf::http::HeaderMap h2 = {
    {"foo", "barbar"},
    {"content-type", "application/json"},
    {"x-custom-header", "custom user data"},
    {"x-MixedCASE", "DontCARE"}};

  ::http::SimpleRequestProcessor sp;
  ::http::RequestParser p(sp);

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
      p.execute(req.data() + done, next);
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
      "GET "
      "/foo/"
      "bar?this=that&awkward=escaped+string+%3A%3B-%3D%3F%21%22%25%23#"
      "AndThisFragment+%3A%3B-%3D%3F%21%22%25%23 "
      "HTTP/1.1\r\n\r\n";

    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp);

    const std::vector<uint8_t> req(request.begin(), request.end());
    p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_GET);
    std::string path_, query_, fragment_;
    std::tie(path_, query_, fragment_) = http::split_url_path(m.url);
    DOCTEST_CHECK(path_ == "/foo/bar");
    DOCTEST_CHECK(
      http::url_decode(query_) ==
      "this=that&awkward=escaped string :;-=?!\"%#");
    DOCTEST_CHECK(http::url_decode(fragment_) == "AndThisFragment :;-=?!\"%#");
  }

  {
    const std::string request =
      "GET "
      "/hello%20world?hello%20world=hello%20world&saluton%20mondo=saluton%"
      "20mondo HTTP/1.1\r\n\r\n";

    http::SimpleRequestProcessor sp;
    http::RequestParser p(sp);

    const std::vector<uint8_t> req(request.begin(), request.end());
    p.execute(req.data(), req.size());

    DOCTEST_CHECK(!sp.received.empty());
    const auto& m = sp.received.front();
    DOCTEST_CHECK(m.method == HTTP_GET);
    std::string path_, query_, fragment_;
    std::tie(path_, query_, fragment_) = http::split_url_path(m.url);
    DOCTEST_CHECK(path_ == "/hello%20world");
    DOCTEST_CHECK(
      http::url_decode(query_) ==
      "hello world=hello world&saluton mondo=saluton mondo");
  }
}

DOCTEST_TEST_CASE("URL parser")
{
  // Test cases taken from https://tools.ietf.org/html/rfc3986
  {
    constexpr auto url_s = "http://www.ietf.org/rfc/rfc2396.txt";
    const auto url = http::parse_url_full(url_s);
    DOCTEST_CHECK(url.scheme == "http");
    DOCTEST_CHECK(url.host == "www.ietf.org");
    DOCTEST_CHECK(url.port.empty());
    DOCTEST_CHECK(url.path == "/rfc/rfc2396.txt");
    DOCTEST_CHECK(url.query.empty());
    DOCTEST_CHECK(url.fragment.empty());
  }

  {
    constexpr auto url_s = "ftp://ftp.is.co.za/rfc/rfc1808.txt";
    const auto url = http::parse_url_full(url_s);
    DOCTEST_CHECK(url.scheme == "ftp");
    DOCTEST_CHECK(url.host == "ftp.is.co.za");
    DOCTEST_CHECK(url.port.empty());
    DOCTEST_CHECK(url.path == "/rfc/rfc1808.txt");
    DOCTEST_CHECK(url.query.empty());
    DOCTEST_CHECK(url.fragment.empty());
  }

  {
    constexpr auto url_s = "foo://example.com";
    const auto url = http::parse_url_full(url_s);
    DOCTEST_CHECK(url.scheme == "foo");
    DOCTEST_CHECK(url.host == "example.com");
    DOCTEST_CHECK(url.port.empty());
    DOCTEST_CHECK(url.path.empty());
    DOCTEST_CHECK(url.query.empty());
    DOCTEST_CHECK(url.fragment.empty());
  }

  {
    constexpr auto url_s = "foo://example.com:8042/over/there?name=ferret#nose";
    const auto url = http::parse_url_full(url_s);
    DOCTEST_CHECK(url.scheme == "foo");
    DOCTEST_CHECK(url.host == "example.com");
    DOCTEST_CHECK(url.port == "8042");
    DOCTEST_CHECK(url.path == "/over/there");
    DOCTEST_CHECK(url.query == "name=ferret");
    DOCTEST_CHECK(url.fragment == "nose");
  }

  {
    constexpr auto url_s =
      "https://[2001:0db8:0000:0000:0000::1428:57ab]:8042/over/there#nose";
    const auto url = http::parse_url_full(url_s);
    DOCTEST_CHECK(url.scheme == "https");
    DOCTEST_CHECK(url.host == "[2001:0db8:0000:0000:0000::1428:57ab]");
    DOCTEST_CHECK(url.port == "8042");
    DOCTEST_CHECK(url.path == "/over/there");
    DOCTEST_CHECK(url.query.empty());
    DOCTEST_CHECK(url.fragment == "nose");
  }

  {
    constexpr auto url_s = "http://[::ffff:0c22:384e]/";
    const auto url = http::parse_url_full(url_s);
    DOCTEST_CHECK(url.scheme == "http");
    DOCTEST_CHECK(url.host == "[::ffff:0c22:384e]");
    DOCTEST_CHECK(url.port.empty());
    DOCTEST_CHECK(url.path == "/");
    DOCTEST_CHECK(url.query.empty());
    DOCTEST_CHECK(url.fragment.empty());
  }
}

DOCTEST_TEST_CASE("Query component decoding")
{
  // Passes plain ASCII through unchanged
  DOCTEST_REQUIRE(ccf::http::decode_query_component("") == "");
  DOCTEST_REQUIRE(
    ccf::http::decode_query_component("plain_ascii123") == "plain_ascii123");

  // '+' is decoded to a space
  DOCTEST_REQUIRE(ccf::http::decode_query_component("a+b+c") == "a b c");

  // %XX escapes are decoded, for both upper and lower case hex digits
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%41%42%43") == "ABC");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%61%62%63") == "abc");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%2f%2F") == "//");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("100%25") == "100%");

  // Truncated escapes at the end of the string are passed through literally,
  // rather than reading out of bounds or throwing
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%") == "%");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("a%") == "a%");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("a%2") == "a%2");

  // Escapes with non-hex-digit characters are passed through literally
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%zz") == "%zz");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%2g") == "%2g");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%g2") == "%g2");

  // Multi-byte (UTF-8) sequences are decoded byte-by-byte, and recombine to
  // the original encoded code point
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%C3%A9") == "\xC3\xA9");

  // '+' and %20 both decode to a space, while %2B is a literal '+'
  DOCTEST_REQUIRE(ccf::http::decode_query_component("a+b%20c") == "a b c");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("a%2Bb%20c") == "a+b c");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%2B") == "+");

  // A literal '%' is kept when it does not begin a valid escape, including
  // immediately before an otherwise-valid escape
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%%41") == "%A");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%41%") == "A%");
  DOCTEST_REQUIRE(ccf::http::decode_query_component("%41%%42") == "A%B");

  // NUL bytes are decoded and preserved (std::string can hold them)
  DOCTEST_REQUIRE(
    ccf::http::decode_query_component("%00") == std::string(1, '\0'));
  DOCTEST_REQUIRE(
    ccf::http::decode_query_component("a%00b") == std::string("a\0b", 3));

  {
    DOCTEST_INFO(
      "Every possible byte value round-trips through percent-encoding and "
      "decode_query_component");
    for (size_t byte = 0; byte < 256; ++byte)
    {
      const auto c = static_cast<char>(byte);

      // '+' is ambiguous with space when percent-encoding is not used, so
      // skip it here (it is covered explicitly above) - every other byte
      // should round-trip when escaped as %XX
      if (c == '+')
      {
        continue;
      }

      const auto escaped =
        fmt::format("%{:02X}", static_cast<unsigned char>(byte));
      const auto decoded = ccf::http::decode_query_component(escaped);
      DOCTEST_REQUIRE(decoded.size() == 1);
      DOCTEST_REQUIRE(decoded[0] == c);
    }
  }
}

DOCTEST_TEST_CASE("Query parser")
{
  constexpr auto query =
    // Handles simple query params
    "foo=bar&baz=123"

    // Handles query params with awkward characters - everything but & and = are
    // ignored
    "&awkward=!?:.-\"===&awkward!key?\"=fine"

    // Parses certain things as empty-string values
    "&empty&also_empty="

    // Splits before URL-decoding each key and value
    "&bar%26baz=tom%26jerry&encoded%3Dkey=encoded%3Dvalue"

    // Malformed or truncated percent-escapes within a key or value are kept
    // literally, rather than being dropped or causing a parse failure
    "&malformed%=oops&trailing%"

    // Will even produce empty-string keys, since it splits at every ampersand
    "&"

    // Maintains every instance of a key, in the order theyre presented
    "&multi=maintains-order!&multi=twice&multi=2&multi=three&multi=1&multi="
    "twice";

  const auto parsed = ccf::http::parse_query(query);

  std::vector<std::string> checked_keys;

#define REQUIRE_PARSED_SINGLE_QUERY_PARAM(K, V) \
  { \
    const auto it = parsed.find(K); \
    DOCTEST_REQUIRE(it != parsed.end()); \
    DOCTEST_REQUIRE(parsed.count(K) == 1); \
    const auto actual = it->second; \
    DOCTEST_REQUIRE(V == actual); \
    checked_keys.push_back(K); \
  }

#define REQUIRE_PARSED_EMPTY_QUERY_PARAM(K) \
  { \
    const auto it = parsed.find(K); \
    DOCTEST_REQUIRE(it != parsed.end()); \
    DOCTEST_REQUIRE(parsed.count(K) == 1); \
    const auto actual = it->second; \
    DOCTEST_REQUIRE(actual.empty()); \
    checked_keys.push_back(K); \
  }

  REQUIRE_PARSED_SINGLE_QUERY_PARAM("foo", "bar");
  REQUIRE_PARSED_SINGLE_QUERY_PARAM("baz", "123");
  REQUIRE_PARSED_SINGLE_QUERY_PARAM("awkward", "!?:.-\"===");
  REQUIRE_PARSED_SINGLE_QUERY_PARAM("awkward!key?\"", "fine");
  REQUIRE_PARSED_EMPTY_QUERY_PARAM("empty");
  REQUIRE_PARSED_EMPTY_QUERY_PARAM("also_empty");
  REQUIRE_PARSED_SINGLE_QUERY_PARAM("bar&baz", "tom&jerry");
  REQUIRE_PARSED_SINGLE_QUERY_PARAM("encoded=key", "encoded=value");
  REQUIRE_PARSED_SINGLE_QUERY_PARAM("malformed%", "oops");
  REQUIRE_PARSED_EMPTY_QUERY_PARAM("trailing%");
  REQUIRE_PARSED_EMPTY_QUERY_PARAM("");

#undef REQUIRE_PARSED_SINGLE_QUERY_PARAM
#undef REQUIRE_PARSED_EMPTY_QUERY_PARAM

  {
    DOCTEST_INFO(
      "Query parser keeps every value when a key is passed multiple times, in "
      "the order they are presented");
    const auto multi_key = "multi";
    DOCTEST_REQUIRE(parsed.count(multi_key) == 6);
    auto range = parsed.equal_range(multi_key);

    auto it = range.first;
    DOCTEST_REQUIRE(it->second == "maintains-order!");

    std::advance(it, 1);
    DOCTEST_REQUIRE(it->second == "twice");

    std::advance(it, 1);
    DOCTEST_REQUIRE(it->second == "2");

    std::advance(it, 1);
    DOCTEST_REQUIRE(it->second == "three");

    std::advance(it, 1);
    DOCTEST_REQUIRE(it->second == "1");

    std::advance(it, 1);
    DOCTEST_REQUIRE(it->second == "twice");

    std::advance(it, 1);
    DOCTEST_REQUIRE(it == range.second);

    checked_keys.push_back(multi_key);
  }

  for (auto it = parsed.begin(); it != parsed.end(); ++it)
  {
    const auto k = it->first;
    const auto found = std::find(checked_keys.begin(), checked_keys.end(), k);
    DOCTEST_REQUIRE(found != checked_keys.end());
  }
}

DOCTEST_TEST_CASE("Query parser edge cases")
{
  {
    // A leading '=' produces an empty key with a (decoded) value
    const auto parsed = ccf::http::parse_query("=value");
    const auto it = parsed.find("");
    DOCTEST_REQUIRE(it != parsed.end());
    DOCTEST_REQUIRE(it->second == "value");
  }

  {
    // A trailing '=' produces an empty value
    const auto parsed = ccf::http::parse_query("key=");
    const auto it = parsed.find("key");
    DOCTEST_REQUIRE(it != parsed.end());
    DOCTEST_REQUIRE(it->second.empty());
  }

  {
    // Splitting happens on the first raw '=' only; a '=' escaped as %3D and an
    // '&' escaped as %26 inside the value are preserved
    const auto parsed = ccf::http::parse_query("k=a=b%26c");
    const auto it = parsed.find("k");
    DOCTEST_REQUIRE(it != parsed.end());
    DOCTEST_REQUIRE(it->second == "a=b&c");
  }
}

DOCTEST_TEST_CASE("Parse Accept header")
{
  {
    const auto fields = ccf::http::parse_accept_header("");
    DOCTEST_REQUIRE(fields.empty());
  }

  {
    const auto fields = ccf::http::parse_accept_header("foo/bar;q=0.25");
    DOCTEST_REQUIRE(fields.size() == 1);
    const auto& field = fields[0];
    DOCTEST_REQUIRE(field.mime_type == "foo");
    DOCTEST_REQUIRE(field.mime_subtype == "bar");
    DOCTEST_REQUIRE(field.q_factor == 0.25f);
  }

  {
    // Shuffled and modified version of Firefox 91 default value, to test
    // sorting
    const auto fields = ccf::http::parse_accept_header(
      "image/webp;q=0.8, "
      "image/*;q=0.8, "
      "text/html, "
      "application/xml;q=0.9, "
      "application/xhtml+xml;q=1.0, "
      "image/avif, "
      "*/*;q=0.8");
    DOCTEST_REQUIRE(fields.size() == 7);

    DOCTEST_REQUIRE(
      fields[0] == ccf::http::AcceptHeaderField{"text", "html", 1.0f});
    DOCTEST_REQUIRE(
      fields[1] == ccf::http::AcceptHeaderField{"image", "avif", 1.0f});
    DOCTEST_REQUIRE(
      fields[2] ==
      ccf::http::AcceptHeaderField{"application", "xhtml+xml", 1.0f});
    DOCTEST_REQUIRE(
      fields[3] == ccf::http::AcceptHeaderField{"application", "xml", 0.9f});
    DOCTEST_REQUIRE(
      fields[4] == ccf::http::AcceptHeaderField{"image", "webp", 0.8f});
    DOCTEST_REQUIRE(
      fields[5] == ccf::http::AcceptHeaderField{"image", "*", 0.8f});
    DOCTEST_REQUIRE(fields[6] == ccf::http::AcceptHeaderField{"*", "*", 0.8f});
  }

  {
    DOCTEST_REQUIRE_THROWS(ccf::http::parse_accept_header("not_a_mime_type"));
    DOCTEST_REQUIRE_THROWS(
      ccf::http::parse_accept_header("valid/mime;q=notnum"));
    DOCTEST_REQUIRE_THROWS(ccf::http::parse_accept_header(","));
  }
}

DOCTEST_TEST_CASE("Accept header MIME matching")
{
  const auto a = ccf::http::AcceptHeaderField{"foo", "bar", 1.0f};
  const auto b = ccf::http::AcceptHeaderField{"foo", "*", 1.0f};
  const auto c = ccf::http::AcceptHeaderField{"*", "*", 1.0f};

  DOCTEST_REQUIRE(a.matches("foo/bar"));
  DOCTEST_REQUIRE_FALSE(a.matches("foo/baz"));
  DOCTEST_REQUIRE_FALSE(a.matches("fob/bar"));
  DOCTEST_REQUIRE_FALSE(a.matches("fob/baz"));

  DOCTEST_REQUIRE(b.matches("foo/bar"));
  DOCTEST_REQUIRE(b.matches("foo/baz"));
  DOCTEST_REQUIRE_FALSE(b.matches("fob/bar"));
  DOCTEST_REQUIRE_FALSE(b.matches("fob/baz"));

  DOCTEST_REQUIRE(c.matches("foo/bar"));
  DOCTEST_REQUIRE(c.matches("foo/baz"));
  DOCTEST_REQUIRE(c.matches("fob/bar"));
  DOCTEST_REQUIRE(c.matches("fob/baz"));
}

DOCTEST_TEST_CASE("Query parser getters")
{
  {
    constexpr auto query = "foo=bar&baz=123";
    const auto parsed = ccf::http::parse_query(query);

    std::string err = "";

    {
      std::string val;
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "foo", val, err));
      DOCTEST_REQUIRE(val == "bar");
      DOCTEST_REQUIRE(err.empty());
    }

    {
      size_t val;
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "baz", val, err));
      DOCTEST_REQUIRE(val == 123);
      DOCTEST_REQUIRE(err.empty());
    }

    {
      std::string val;
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "baz", val, err));
      DOCTEST_REQUIRE(val == "123");
      DOCTEST_REQUIRE(err.empty());
    }

    {
      size_t val;
      DOCTEST_REQUIRE(!ccf::http::get_query_value(parsed, "foo", val, err));
      DOCTEST_REQUIRE(err == "Unable to parse value 'bar' in parameter 'foo'");
    }
  }

  {
    constexpr auto query = "t=true&f=false&fnf=filenotfound";
    const auto parsed = ccf::http::parse_query(query);
    std::string err = "";

    {
      bool val = false;
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "t", val, err));
      DOCTEST_REQUIRE(val == true);
      DOCTEST_REQUIRE(err.empty());
    }

    {
      bool val = true;
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "f", val, err));
      DOCTEST_REQUIRE(val == false);
      DOCTEST_REQUIRE(err.empty());
    }

    {
      bool val;
      DOCTEST_REQUIRE(!ccf::http::get_query_value(parsed, "fnf", val, err));
      DOCTEST_REQUIRE(
        err ==
        "Unable to parse value 'filenotfound' as bool in parameter 'fnf'");
    }
  }

  {
    DOCTEST_INFO("Signed integral types accept negative values");
    constexpr auto query = "neg=-42&pos=42";
    const auto parsed = ccf::http::parse_query(query);
    std::string err;

    {
      int val = 0;
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "neg", val, err));
      DOCTEST_REQUIRE(val == -42);
      DOCTEST_REQUIRE(err.empty());
    }

    {
      // Unsigned types correctly reject a negative value, rather than
      // wrapping around to a large positive value
      size_t val = 0;
      DOCTEST_REQUIRE(!ccf::http::get_query_value(parsed, "neg", val, err));
      DOCTEST_REQUIRE(err == "Unable to parse value '-42' in parameter 'neg'");
    }

    {
      uint8_t val = 0;
      err.clear();
      DOCTEST_REQUIRE(ccf::http::get_query_value(parsed, "pos", val, err));
      DOCTEST_REQUIRE(val == 42);
      DOCTEST_REQUIRE(err.empty());
    }
  }

  {
    DOCTEST_INFO(
      "Values which overflow the target integral type, or contain trailing "
      "garbage, are rejected rather than silently truncated");
    constexpr auto query =
      "overflow=999999999999999999999999&trailing=123abc&"
      "leading_space= 123&hex=0x1A";
    const auto parsed = ccf::http::parse_query(query);
    std::string err;

    {
      uint8_t val = 0;
      DOCTEST_REQUIRE(
        !ccf::http::get_query_value(parsed, "overflow", val, err));
    }

    {
      int val = 0;
      DOCTEST_REQUIRE(
        !ccf::http::get_query_value(parsed, "trailing", val, err));
    }

    {
      int val = 0;
      DOCTEST_REQUIRE(
        !ccf::http::get_query_value(parsed, "leading_space", val, err));
    }

    {
      // from_chars parses decimal by default, so a hex-prefixed string is
      // parsed only up to the invalid 'x', and rejected as trailing garbage
      int val = 0;
      DOCTEST_REQUIRE(!ccf::http::get_query_value(parsed, "hex", val, err));
    }
  }

  {
    DOCTEST_INFO("Percent-escaped integral values are decoded before parsing");
    constexpr auto query = "escaped_neg=%2D42";
    const auto parsed = ccf::http::parse_query(query);
    std::string err;

    int val = 0;
    DOCTEST_REQUIRE(
      ccf::http::get_query_value(parsed, "escaped_neg", val, err));
    DOCTEST_REQUIRE(val == -42);
    DOCTEST_REQUIRE(err.empty());
  }
}

DOCTEST_TEST_CASE("parse_want_repr_digest - single supported algorithm")
{
  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("sha-256=1");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("sha-384=5");
    DOCTEST_CHECK(algo == "sha-384");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA384);
  }

  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("sha-512=10");
    DOCTEST_CHECK(algo == "sha-512");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA512);
  }
}

DOCTEST_TEST_CASE(
  "parse_want_repr_digest - multiple algorithms with priorities")
{
  {
    auto [algo, md] =
      ccf::http::parse_want_repr_digest("sha-256=1, sha-512=10");
    DOCTEST_CHECK(algo == "sha-512");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA512);
  }

  {
    auto [algo, md] =
      ccf::http::parse_want_repr_digest("sha-512=3, sha-256=7, sha-384=5");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    auto [algo, md] =
      ccf::http::parse_want_repr_digest("sha-384=10, sha-256=10");
    // Equal preference - first one wins
    DOCTEST_CHECK(algo == "sha-384");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA384);
  }
}

DOCTEST_TEST_CASE("parse_want_repr_digest - unknown algorithms are ignored")
{
  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("md5=10, sha-256=1");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    auto [algo, md] =
      ccf::http::parse_want_repr_digest("crc32=5, sha-384=3, unknown=10");
    DOCTEST_CHECK(algo == "sha-384");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA384);
  }
}

DOCTEST_TEST_CASE("parse_want_repr_digest - defaults to sha-256 when no match")
{
  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("md5=10");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("unknown=5");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }
}

DOCTEST_TEST_CASE("parse_want_repr_digest - malformed entries are skipped")
{
  {
    // Preference of 0 is invalid (must be >= 1)
    auto [algo, md] = ccf::http::parse_want_repr_digest("sha-256=0");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    // Negative preference is invalid
    auto [algo, md] = ccf::http::parse_want_repr_digest("sha-512=-1");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    // Non-numeric preference is skipped, but valid entry is used
    auto [algo, md] =
      ccf::http::parse_want_repr_digest("sha-256=abc, sha-384=5");
    DOCTEST_CHECK(algo == "sha-384");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA384);
  }
}

DOCTEST_TEST_CASE("parse_want_repr_digest - whitespace handling")
{
  {
    auto [algo, md] = ccf::http::parse_want_repr_digest("  sha-256 = 1  ");
    DOCTEST_CHECK(algo == "sha-256");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA256);
  }

  {
    auto [algo, md] =
      ccf::http::parse_want_repr_digest("sha-256=1 , sha-512=10");
    DOCTEST_CHECK(algo == "sha-512");
    DOCTEST_CHECK(md == ccf::crypto::MDType::SHA512);
  }
}

DOCTEST_TEST_CASE(
  "parse_want_repr_digest - algorithm without explicit preference")
{
  // No "=" means preference defaults to 1
  auto [algo, md] = ccf::http::parse_want_repr_digest("sha-512");
  DOCTEST_CHECK(algo == "sha-512");
  DOCTEST_CHECK(md == ccf::crypto::MDType::SHA512);
}
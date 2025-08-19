// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/key_pair.h"
#include "ccf/http_accept.h"
#include "ccf/http_query.h"
#include "http/http_builder.h"
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
}

DOCTEST_TEST_CASE("Query parser with URL-encoded ampersands")
{
  {
    // Test the issue described in #6745: URL-encoded ampersands should be 
    // treated as literal ampersands in parameter keys and values
    const std::string request =
      "GET "
      "/foo?bar%26baz=tom%26jerry "
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
    DOCTEST_CHECK(path_ == "/foo");
    DOCTEST_CHECK(query_ == "bar%26baz=tom%26jerry");
    
    // Parse the query - this should handle URL-encoded strings properly
    const auto parsed = ccf::http::parse_query(query_);
    
    // Should have exactly one parameter with key "bar&baz" and value "tom&jerry"
    DOCTEST_CHECK(parsed.size() == 1);
    
    std::string err = "";
    std::string val;
    DOCTEST_CHECK(ccf::http::get_query_value(parsed, "bar&baz", val, err));
    DOCTEST_CHECK(val == "tom&jerry");
    DOCTEST_CHECK(err.empty());
  }
  
  {
    // Test multiple parameters with URL-encoded ampersands
    const std::string query = "key1%26special=value1%26more&normal=simple";
    const auto parsed = ccf::http::parse_query(query);
    
    // Should have exactly two parameters
    DOCTEST_CHECK(parsed.size() == 2);
    
    std::string err = "";
    std::string val;
    
    // First parameter: key "key1&special" with value "value1&more"
    DOCTEST_CHECK(ccf::http::get_query_value(parsed, "key1&special", val, err));
    DOCTEST_CHECK(val == "value1&more");
    DOCTEST_CHECK(err.empty());
    
    // Second parameter: key "normal" with value "simple"
    DOCTEST_CHECK(ccf::http::get_query_value(parsed, "normal", val, err));
    DOCTEST_CHECK(val == "simple");
    DOCTEST_CHECK(err.empty());
  }
  
  {
    // Test URL-encoded equals signs in keys and values
    const std::string query = "key%3Dname=value%3Ddata&simple=test";
    const auto parsed = ccf::http::parse_query(query);
    
    // Should have exactly two parameters
    DOCTEST_CHECK(parsed.size() == 2);
    
    std::string err = "";
    std::string val;
    
    // First parameter: key "key=name" with value "value=data"
    DOCTEST_CHECK(ccf::http::get_query_value(parsed, "key=name", val, err));
    DOCTEST_CHECK(val == "value=data");
    DOCTEST_CHECK(err.empty());
    
    // Second parameter: key "simple" with value "test"
    DOCTEST_CHECK(ccf::http::get_query_value(parsed, "simple", val, err));
    DOCTEST_CHECK(val == "test");
    DOCTEST_CHECK(err.empty());
  }
}
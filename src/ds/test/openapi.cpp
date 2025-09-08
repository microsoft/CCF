// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/openapi.h"

#include "ccf/http_consts.h"
#include "ds/internal_logger.h.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace ccf::ds;

#define REQUIRE_ELEMENT(j, name, type_fn) \
  { \
    const auto name##_it = j.find(#name); \
    REQUIRE(name##_it != j.end()); \
    REQUIRE(name##_it->type_fn()); \
  }

static constexpr auto server_url = "https://not.a.real.server.com/testing_only";

// This is only a very basic check - assume full validation is done by external
// validator
void required_doc_elements(const nlohmann::json& j)
{
  REQUIRE_ELEMENT(j, openapi, is_string);
  REQUIRE_ELEMENT(j, info, is_object);
  REQUIRE_ELEMENT(j, paths, is_object);
}

TEST_CASE("Manual construction")
{
  auto doc = openapi::create_document(
    "Test generated API",
    "Some longer description enhanced with **Markdown**",
    "0.1.42");

  openapi::server(doc, server_url);

  const auto string_schema = nlohmann::json{{"type", "string"}};

  auto& foo = openapi::path(doc, "/users/foo");
  auto& foo_post = openapi::path_operation(foo, HTTP_POST);
  auto& foo_post_request = openapi::request_body(foo_post);
  auto& foo_post_request_json = openapi::media_type(
    foo_post_request, ccf::http::headervalues::contenttype::JSON);
  auto& foo_post_request_json_schema = openapi::schema(foo_post_request_json);
  foo_post_request_json_schema = string_schema;

  auto& foo_post_response_ok = openapi::response(
    foo_post, HTTP_STATUS_OK, "Indicates that everything went ok");
  auto& foo_post_response_ok_json = openapi::media_type(
    foo_post_response_ok, ccf::http::headervalues::contenttype::JSON);
  auto& foo_post_response_ok_json_schema =
    openapi::schema(foo_post_response_ok_json);
  foo_post_response_ok_json_schema = string_schema;

  required_doc_elements(doc);

  const auto& info_element = doc["info"];
  REQUIRE_ELEMENT(info_element, title, is_string);
  REQUIRE_ELEMENT(info_element, description, is_string);
  REQUIRE_ELEMENT(info_element, version, is_string);

  REQUIRE_ELEMENT(doc, servers, is_array);
  const auto& servers_element = doc["servers"];
  REQUIRE(servers_element.size() == 1);
  const auto& first_server = servers_element[0];
  REQUIRE_ELEMENT(first_server, url, is_string);
}

struct Foo
{
  size_t n;
  std::string s;
};
DECLARE_JSON_TYPE(Foo);
DECLARE_JSON_REQUIRED_FIELDS(Foo, n, s);

TEST_CASE("Simple custom types")
{
  auto doc = openapi::create_document(
    "Test generated API",
    "Some longer description enhanced with **Markdown**",
    "0.1.42");

  openapi::server(doc, server_url);

  openapi::add_request_body_schema<Foo>(doc, "/app/foo", HTTP_POST);
  openapi::add_response_schema<size_t>(
    doc, "/app/foo", HTTP_POST, HTTP_STATUS_OK);
  openapi::add_response_schema<Foo>(doc, "/app/foo", HTTP_POST, HTTP_STATUS_OK);

  required_doc_elements(doc);
}

struct Bar
{
  std::string name;
  double f;
};
DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Bar);
DECLARE_JSON_REQUIRED_FIELDS(Bar, name);
DECLARE_JSON_OPTIONAL_FIELDS(Bar, f);

enum class Vehicle
{
  Car,
  Pedalo,
  Submarine,
};

DECLARE_JSON_ENUM(
  Vehicle,
  {{Vehicle::Car, "vroom vroom"},
   {Vehicle::Pedalo, "splash splash"},
   {Vehicle::Submarine, "glug glug"}});

struct Baz : public Bar
{
  uint16_t n;
  double x;
  double y;
  Vehicle v;
};
DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(Baz, Bar);
DECLARE_JSON_REQUIRED_FIELDS(Baz, n, v);
DECLARE_JSON_OPTIONAL_FIELDS(Baz, x, y);

struct Buzz : public Baz
{
  Foo required_and_only_in_c;
  uint16_t optional_and_only_in_c;
};
DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(Buzz, Baz);
DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
  Buzz, required_and_only_in_c, "RequiredJsonField");
DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
  Buzz, optional_and_only_in_c, "OptionalJsonField");

TEST_CASE("Complex custom types")
{
  auto doc = openapi::create_document(
    "Test generated API",
    "Some longer description enhanced with **Markdown**",
    "0.1.42");

  openapi::server(doc, server_url);

  openapi::add_response_schema<std::vector<Foo>>(
    doc, "/app/foos", HTTP_GET, HTTP_STATUS_OK);
  openapi::add_response_schema<std::vector<std::vector<Foo>>>(
    doc, "/app/fooss", HTTP_GET, HTTP_STATUS_OK);
  openapi::add_response_schema<Bar>(doc, "/app/bar", HTTP_GET, HTTP_STATUS_OK);
  openapi::add_response_schema<Baz>(doc, "/app/baz", HTTP_GET, HTTP_STATUS_OK);
  openapi::add_response_schema<std::map<std::string, Buzz>>(
    doc, "/app/buzz", HTTP_GET, HTTP_STATUS_OK);

  openapi::add_request_body_schema<std::optional<Bar>>(
    doc, "/app/complex", HTTP_POST);
  openapi::add_response_schema<std::map<Baz, std::vector<Buzz>>>(
    doc, "/app/complex", HTTP_POST, HTTP_STATUS_OK);
  openapi::add_response_schema<std::unordered_set<Baz>>(
    doc, "/app/complex", HTTP_POST, HTTP_STATUS_OK);

  required_doc_elements(doc);
}

// Required functions may be implemented manually, allowing the type to be used
// in macro for a containing type
namespace aaa
{
  struct FriendlyName
  {
    std::string forename;
    std::string nickname;
    std::string surname;
  };

  void to_json(nlohmann::json& j, const FriendlyName& fn)
  {
    j = fmt::format("{} \"{}\" {}", fn.forename, fn.nickname, fn.surname);
  }

  void from_json(const nlohmann::json& j, FriendlyName& fn)
  {
    const auto s = j.get<std::string>();
    const auto nickname_start = s.find('"');
    const auto nickname_end = s.find('"', nickname_start + 1);
    fn.forename = s.substr(0, nickname_start - 1);
    fn.nickname =
      s.substr(nickname_start + 1, nickname_end - nickname_start - 1);
    fn.surname = s.substr(nickname_end + 2);
  }

  std::string schema_name(const FriendlyName*)
  {
    return "FriendlyName";
  }

  template <typename T>
  void add_schema_components(T& doc, nlohmann::json& j, const FriendlyName*)
  {
    j["type"] = "string";
    j["pattern"] = "^.* \".*\" .*$";
  }
}

namespace bbb
{
  struct Person
  {
    aaa::FriendlyName name;
    size_t age;
  };
  DECLARE_JSON_TYPE(Person);
  DECLARE_JSON_REQUIRED_FIELDS(Person, name, age);
}

TEST_CASE("Manual function definitions")
{
  {
    INFO("FriendlyName roundtrip");
    aaa::FriendlyName fn;
    fn.forename = "Dwayne";
    fn.nickname = "The Rock";
    fn.surname = "Johnson";
    const nlohmann::json j = fn;
    const auto fn2 = j.get<aaa::FriendlyName>();
    CHECK(fn.forename == fn2.forename);
    CHECK(fn.nickname == fn2.nickname);
    CHECK(fn.surname == fn2.surname);

    bbb::Person p;
    p.name = fn;
    p.age = 42;
    const nlohmann::json j2 = p;
    const auto p2 = j2.get<bbb::Person>();
    CHECK(p.name.forename == p2.name.forename);
    CHECK(p.name.nickname == p2.name.nickname);
    CHECK(p.name.surname == p2.name.surname);
    CHECK(p.age == p2.age);
  }

  {
    INFO("OpenAPI generation");
    auto doc = openapi::create_document(
      "Test generated API",
      "Some longer description enhanced with **Markdown**",
      "0.1.42");

    openapi::add_request_body_schema<bbb::Person>(doc, "/person", HTTP_POST);

    const auto components_schemas = doc["components"]["schemas"];
    REQUIRE(components_schemas.find("Person") != components_schemas.end());
    aaa::FriendlyName* fn = nullptr;
    REQUIRE(
      components_schemas.find(aaa::schema_name(fn)) !=
      components_schemas.end());
  }
}

TEST_CASE("sanitise_components_key")
{
  using namespace ccf::ds::openapi;

  CHECK(sanitise_components_key("User") == "User");
  CHECK(sanitise_components_key("User_1") == "User_1");
  CHECK(sanitise_components_key("User_Name") == "User_Name");
  CHECK(sanitise_components_key("user-name") == "user-name");
  CHECK(sanitise_components_key("my.org.User") == "my.org.User");

  CHECK(
    sanitise_components_key(
      "abdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ 0123456789") ==
    "abdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789");
  CHECK(sanitise_components_key("!\"$%^&*()") == "_________");
  CHECK(
    sanitise_components_key(";:'@#~[{]}-_=+/?.>,<\\|") ==
    "__________-_____._____");
}
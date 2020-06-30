// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/openapi.h"

#include "http/http_consts.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace ds;

void print_doc(const std::string& title, const nlohmann::json& doc)
{
  std::cout << title << std::endl;
  std::cout << doc.dump(2) << std::endl;
}

#define REQUIRE_ELEMENT(j, name, type_fn) \
  { \
    const auto name##_it = j.find(#name); \
    REQUIRE(name##_it != j.end()); \
    REQUIRE(name##_it->type_fn()); \
  }

static constexpr auto server_url =
  "https://not.a.real.server.example.com/testing_only";

// TODO: Use some external verifier to check this. What we primarily care about
// is "is this a valid OpenAPI doc". We don't even really care about parsing it
// for specific elements, just producing it
void required_doc_elements(const nlohmann::json& j)
{
  REQUIRE_ELEMENT(j, openapi, is_string);
  REQUIRE_ELEMENT(j, info, is_object);
  REQUIRE_ELEMENT(j, paths, is_object);
}

TEST_CASE("Required elements")
{
  openapi::Document doc;

  const nlohmann::json j = doc;
  required_doc_elements(j);
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
    foo_post_request, http::headervalues::contenttype::JSON);
  foo_post_request_json["schema"] = string_schema;
  auto& foo_post_response_ok = openapi::response(
    foo_post, HTTP_STATUS_OK, "Indicates that everything went ok");
  auto& foo_post_response_ok_json = openapi::media_type(
    foo_post_response_ok, http::headervalues::contenttype::JSON);
  foo_post_response_ok_json["schema"] = string_schema;

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

  print_doc("PATHS", doc);
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
  openapi::Document doc;
  doc.info.title = "Test generated API";
  doc.info.description = "Some longer description enhanced with **Markdown**";
  doc.info.version = "0.1.42";

  {
    openapi::Server mockup_server;
    mockup_server.url = server_url;
    doc.servers.push_back(mockup_server);
  }

  doc.add_request_body_schema<Foo>(
    "/app/foo", HTTP_POST, http::headervalues::contenttype::JSON);
  doc.add_response_schema<size_t>(
    "/app/foo",
    HTTP_POST,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);
  doc.add_response_schema<Foo>(
    "/app/foo",
    HTTP_GET,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);

  const nlohmann::json j = doc;
  required_doc_elements(j);

  print_doc("SIMPLE", doc);
}

struct Bar
{
  std::string name;
  double f;
};
DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Bar);
DECLARE_JSON_REQUIRED_FIELDS(Bar, name);
DECLARE_JSON_OPTIONAL_FIELDS(Bar, f);

struct Baz : public Bar
{
  uint16_t n;
  double x;
  double y;
};
DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(Baz, Bar);
DECLARE_JSON_REQUIRED_FIELDS(Baz, n);
DECLARE_JSON_OPTIONAL_FIELDS(Baz, x, y);

struct Buzz : public Baz
{
  Foo required_and_only_in_c;
  uint16_t optional_and_only_in_c;
};
DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(Buzz, Baz);
DECLARE_JSON_REQUIRED_FIELDS_WITH_RENAMES(
  Buzz, required_and_only_in_c, RequiredJsonField);
DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(
  Buzz, optional_and_only_in_c, OptionalJsonField);

TEST_CASE("Complex custom types")
{
  openapi::Document doc;
  doc.info.title = "Test generated API";
  doc.info.description = "Some longer description enhanced with **Markdown**";
  doc.info.version = "0.1.42";

  doc.add_response_schema<std::vector<Foo>>(
    "/app/foos",
    HTTP_GET,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);
  doc.add_response_schema<Bar>(
    "/app/bar",
    HTTP_GET,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);
  doc.add_response_schema<Baz>(
    "/app/baz",
    HTTP_GET,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);
  doc.add_response_schema<Buzz>(
    "/app/buzz",
    HTTP_GET,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);
  doc.add_request_body_schema<std::optional<Bar>>(
    "/app/complex", HTTP_GET, http::headervalues::contenttype::JSON);
  doc.add_response_schema<std::map<Baz, std::vector<Buzz>>>(
    "/app/complex",
    HTTP_GET,
    HTTP_STATUS_OK,
    http::headervalues::contenttype::JSON);

  const nlohmann::json j = doc;
  required_doc_elements(j);

  print_doc("COMPLEX", doc);
}
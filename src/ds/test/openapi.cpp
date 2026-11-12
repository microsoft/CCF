// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/openapi.h"

#include "ccf/http_consts.h"
#include "ccf/json.h"
#include "ds/internal_logger.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <set>
#include <tuple>
#include <variant>

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
  CHECK(doc.at("openapi") == "3.1.0");
  CHECK(
    doc.at("jsonSchemaDialect") ==
    "https://json-schema.org/draft/2020-12/schema");

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

namespace std
{
  template <>
  struct hash<Baz>
  {
    size_t operator()(const Baz& b) const
    {
      return std::hash<uint16_t>()(b.n);
    }
  };
}

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
    j = doc.template add_schema_component<std::string>();
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

  for (size_t repetition = 0; repetition < 2; ++repetition)
  {
    INFO("OpenAPI generation");
    auto doc = openapi::create_document(
      "Test generated API",
      "Some longer description enhanced with **Markdown**",
      "0.1.42");

    openapi::SchemaHelper helper{doc};
    helper.add_schema_component<aaa::FriendlyName>();
    openapi::add_request_body_schema<bbb::Person>(doc, "/person", HTTP_POST);

    const auto components_schemas = doc["components"]["schemas"];
    REQUIRE(components_schemas.find("Person") != components_schemas.end());
    aaa::FriendlyName* fn = nullptr;
    REQUIRE(
      components_schemas.find(aaa::schema_name(fn)) !=
      components_schemas.end());
  }
}

struct WithRequiredOptionalField
{
  std::optional<Foo> maybe_foo;
};

DECLARE_JSON_TYPE(WithRequiredOptionalField);
DECLARE_JSON_REQUIRED_FIELDS(WithRequiredOptionalField, maybe_foo);

TEST_CASE(
  "Required optional field produces nullable component schema, not "
  "generated output")
{
  // Regression test: a std::optional<T> field which is JSON-required (always
  // present, but may hold a null value - e.g.
  // ccf::kv::ConsensusDetails::primary_id while no primary is known) must
  // produce a schema that permits null, in addition to the ref/inline schema
  // for T. See https://github.com/microsoft/CCF/issues/8323.
  auto doc = openapi::create_document(
    "Test generated API",
    "Some longer description enhanced with **Markdown**",
    "0.1.42");

  openapi::server(doc, server_url);

  openapi::add_response_schema<WithRequiredOptionalField>(
    doc, "/app/required_optional", HTTP_GET, HTTP_STATUS_OK);

  const auto& components_schemas = doc["components"]["schemas"];
  const auto it = components_schemas.find("WithRequiredOptionalField");
  REQUIRE(it != components_schemas.end());

  const auto& schema = *it;
  REQUIRE(schema.contains("required"));
  const auto& required = schema["required"];
  bool found_required = false;
  for (const auto& field : required)
  {
    if (field == "maybe_foo")
    {
      found_required = true;
    }
  }
  REQUIRE(found_required);

  const auto& properties = schema["properties"];
  const auto prop_it = properties.find("maybe_foo");
  REQUIRE(prop_it != properties.end());
  const auto& maybe_foo_schema = *prop_it;

  REQUIRE(maybe_foo_schema.contains("anyOf"));
  const auto& any_of = maybe_foo_schema["anyOf"];
  REQUIRE(any_of.is_array());
  REQUIRE(any_of.size() == 2);
  auto inner = any_of[0];
  if (inner.contains("$ref"))
  {
    const auto pointer = inner.at("$ref").get<std::string>().substr(1);
    inner = doc.at(nlohmann::json::json_pointer(pointer));
  }
  CHECK(inner.at("type") == "object");
  CHECK(inner.at("properties").contains("n"));
  CHECK(inner.at("properties").contains("s"));
  CHECK(any_of[1] == nlohmann::json{{"type", "null"}});
}

struct RecursiveSchemaSample
{
  std::string label;
  std::vector<RecursiveSchemaSample> children;
  std::tuple<int32_t, std::string> position = {1, "row"};
  std::variant<int32_t, double> choice = 7;
};

CCF_JSON_TYPE(
  RecursiveSchemaSample, CCF_JSON_REQUIRED(label, children, position, choice));

struct SharedSchemaResponse
{
  Foo item;
  Vehicle vehicle;
};

CCF_JSON_TYPE(SharedSchemaResponse, CCF_JSON_REQUIRED(item, vehicle));

struct OtherSchemaResponse
{
  Foo item;
};

CCF_JSON_TYPE(OtherSchemaResponse, CCF_JSON_REQUIRED(item));

enum class DocumentedMode
{
  Active,
  Retired
};
CCF_JSON_ENUM(
  DocumentedMode,
  "active",
  DocumentedMode::Active,
  "retired",
  DocumentedMode::Retired);

template <>
struct glz::json_schema<DocumentedMode>
{
  glz::schema active{.title = "Writable", .description = "Accepts new records"};
};

TEST_CASE("Enum schemas retain genuine per-value metadata")
{
  const auto schema = ccf::json::schema<DocumentedMode>();
  CHECK(schema.at("oneOf").at(0).at("description") == "Accepts new records");
  CHECK(schema.at("oneOf").at(0).at("title") == "Writable");
  CHECK_FALSE(schema.contains("enum"));
}

TEST_CASE("Custom local definitions become resolvable shared components")
{
  using Json = nlohmann::json;
  const Json custom = {
    {"type", "object"},
    {"$defs", {{"item", {{"type", "integer"}}}}},
    {"properties",
     {{"value", {{"$ref", "#/$defs/ccf.adl.Custom/$defs/item"}}}}}};
  const Json source = {
    {"$ref", "#/$defs/ccf.adl.Custom"},
    {"$defs", {{"ccf.adl.Custom", custom}}}};
  Json components = Json::object();
  const std::string root = "Root";
  const auto reference =
    ccf::json::detail::ComponentSchemas(source, root, root, components)
      .rewrite(source);
  CHECK(reference.at("$ref") == "#/components/schemas/Custom");
  Json document = {{"components", {{"schemas", components}}}};
  const auto flattened = document.flatten();
  for (const auto& [path, value] : flattened.items())
  {
    CHECK(path.find("/$defs/") == std::string::npos);
    if (path.ends_with("/$ref"))
    {
      CHECK_NOTHROW(
        document.at(Json::json_pointer(value.get<std::string>().substr(1))));
    }
  }
}

TEST_CASE("Recursive records may be reached through aliases")
{
  using Json = nlohmann::json;
  Json source = {
    {"$ref", "#/$defs/A"},
    {"$defs",
     {{"A", {{"$ref", "#/$defs/B"}}},
      {"B",
       {{"type", "object"},
        {"properties", {{"next", {{"$ref", "#/$defs/A"}}}}}}}}}};
  Json components = Json::object();
  const std::string root = "Root";
  ccf::json::detail::ComponentSchemas packaged(source, root, root, components);
  CHECK(packaged.rewrite(source).at("$ref") == "#/components/schemas/B");
  CHECK(
    components.at("B").at("properties").at("next").at("$ref") ==
    "#/components/schemas/B");
  source["$defs"]["B"] = Json{{"$ref", "#/$defs/A"}};
  ccf::json::detail::ComponentSchemas cyclic(source, root, root, components);
  CHECK_THROWS_AS(cyclic.rewrite(source), std::logic_error);
}

TEST_CASE("OpenAPI shares named types and inlines primitives document-wide")
{
  auto doc = openapi::create_document("Shared schemas", "", "1");
  openapi::SchemaHelper helper{doc};
  helper.add_schema_component<SharedSchemaResponse>();
  helper.add_schema_component<OtherSchemaResponse>();
  const auto& schemas = doc.at("components").at("schemas");
  CHECK(
    schemas.at("SharedSchemaResponse").at("properties").at("item") ==
    nlohmann::json{{"$ref", "#/components/schemas/Foo"}});
  CHECK(
    schemas.at("OtherSchemaResponse").at("properties").at("item") ==
    nlohmann::json{{"$ref", "#/components/schemas/Foo"}});
  CHECK(schemas.at("Foo").at("properties").at("n").at("type") == "integer");
  CHECK(schemas.at("Vehicle").at("enum").size() == 3);
  CHECK_FALSE(schemas.at("Vehicle").contains("oneOf"));
  for (const auto& schema : schemas)
  {
    CHECK_FALSE(schema.contains("$defs"));
    CHECK_FALSE(schema.contains("title"));
    CHECK_FALSE(schema.contains("additionalProperties"));
  }
}

TEST_CASE("Native tuple, variant and recursive schemas retain their contracts")
{
  using Json = nlohmann::json;
  const auto tuple = ccf::json::schema<std::tuple<int32_t, std::string>>();
  CHECK(tuple.at("prefixItems").size() == 2);
  CHECK(tuple.at("items") == false);
  CHECK(tuple.at("minItems") == 2);
  CHECK(tuple.at("maxItems") == 2);
  const auto variant = ccf::json::schema<std::variant<int32_t, double>>();
  CHECK(variant.at("anyOf").size() == 2);
  CHECK_FALSE(variant.contains("oneOf"));

  auto doc = openapi::create_document("Recursive schema", "", "1");
  openapi::SchemaHelper helper{doc};
  const auto reference = helper.add_schema_component<RecursiveSchemaSample>();
  const auto snapshot = doc;
  CHECK(helper.add_schema_component<RecursiveSchemaSample>() == reference);
  CHECK(doc == snapshot);
  size_t references = 0;
  const auto flattened = doc.flatten();
  for (const auto& [path, value] : flattened.items())
  {
    if (path.ends_with("/$ref"))
    {
      const auto target = value.get<std::string>();
      REQUIRE(target.starts_with("#/components/schemas/"));
      CHECK_NOTHROW(doc.at(Json::json_pointer(target.substr(1))));
      ++references;
    }
  }
  CHECK(references > 0);
  CHECK_THROWS_WITH(
    ccf::ds::json::build_schema<RecursiveSchemaSample>(),
    "Recursive schemas require a component schema");
  const RecursiveSchemaSample tree{"root", {{"child", {}}}};
  const auto wire = ccf::json::write(tree);
  CHECK(ccf::json::write(ccf::json::read<RecursiveSchemaSample>(wire)) == wire);
}

TEST_CASE("Schema packaging preserves reference constraints and instance data")
{
  using Json = nlohmann::json;
  const Json data = {{"$ref", "#/instance"}, {"additionalProperties", false}};
  const Json schema = {
    {"$ref", "#/$defs/count"},
    {"title", "User label"},
    {"maximum", 7},
    {"default", data},
    {"examples", Json::array({data})},
    {"$defs", {{"count", {{"type", "integer"}, {"minimum", 0}}}}}};
  CHECK(ccf::json::detail::prepare_schema(schema) == schema);
  const auto packaged =
    ccf::json::detail::rebase_schema(schema, "#/components/schemas/Example");
  CHECK(packaged.at("$ref") == "#/components/schemas/Example/$defs/count");
  CHECK(packaged.at("maximum") == 7);
  CHECK(packaged.at("title") == "User label");
  CHECK(packaged.at("default") == data);
  CHECK(packaged.at("examples") == Json::array({data}));
  std::set<std::string> expanding;
  const auto inlined =
    ccf::json::detail::inline_references(schema, schema, expanding);
  REQUIRE(inlined.at("allOf").size() == 2);
  CHECK(inlined.at("allOf").at(0).at("minimum") == 0);
  CHECK(inlined.at("allOf").at(1).at("maximum") == 7);
  CHECK_THROWS_AS(
    ccf::json::detail::rebase_schema(
      Json{{"$ref", "#/$defs/missing"}}, "#/components/schemas/Bad"),
    Json::out_of_range);
}

TEST_CASE("Omitting record defaults retains map constraints and custom schemas")
{
  using Json = nlohmann::json;
  const Json closed = {
    {"type", "object"}, {"additionalProperties", false}, {"title", "Explicit"}};
  const Json schema = {
    {"type", "object"},
    {"additionalProperties", false},
    {"properties",
     {{"map",
       {{"type", "object"}, {"additionalProperties", {{"type", "integer"}}}}}}},
    {"$defs", {{"ccf.adl.Closed", closed}}}};
  const auto prepared = ccf::json::detail::prepare_schema(schema);
  CHECK_FALSE(prepared.contains("additionalProperties"));
  CHECK(
    prepared.at("properties").at("map").at("additionalProperties") ==
    Json{{"type", "integer"}});
  CHECK(prepared.at("$defs").at("ccf.adl.Closed") == closed);
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
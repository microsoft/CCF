// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/json.h"
#include "ccf/kv/serialisers/json_serialiser.h"
#include "ccf/tx_id.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

namespace
{
  using Json = nlohmann::json;

  struct Base
  {
    int id = 7;
    int retries = 7;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Base);
  DECLARE_JSON_REQUIRED_FIELDS(Base, id);
  DECLARE_JSON_OPTIONAL_FIELDS(Base, retries);

  struct Record : Base
  {
    std::optional<ccf::TxID> transaction_id;
    std::vector<uint8_t> bytes;
    std::map<std::string, std::string> labels;
    std::optional<std::string> next_link;
  };

  DECLARE_JSON_TYPE_WITH_BASE_AND_OPTIONAL_FIELDS(Record, Base);
  DECLARE_JSON_REQUIRED_FIELDS(Record, transaction_id, bytes, labels);
  DECLARE_JSON_OPTIONAL_FIELDS_WITH_RENAMES(Record, next_link, "@nextLink");

  struct NewRecord
  {
    int id = 7;
    std::string message;
    int priority = 7;
  };

  CCF_JSON_TYPE(
    NewRecord,
    CCF_JSON_REQUIRED(id, message),
    CCF_JSON_ALLOW_MISSING(priority));

  enum class Mode
  {
    Active,
    Retired,
    Unmapped
  };

  CCF_JSON_ENUM(Mode, "active", Mode::Active, "retired", Mode::Retired);

  struct WithMode
  {
    Mode mode = Mode::Active;
  };

  CCF_JSON_TYPE(WithMode, CCF_JSON_REQUIRED(mode));

  struct NativeOnly
  {
    int id = 7;
  };

  CCF_JSON_FIELDS(NativeOnly, CCF_JSON_REQUIRED(id));

  void to_json(Json&, const NativeOnly&)
  {
    throw std::logic_error("DOM conversion must not be used");
  }

  void from_json(const Json&, NativeOnly&)
  {
    throw std::logic_error("DOM conversion must not be used");
  }

  struct Defaulted
  {
    static inline size_t constructions = 0;
    int a = 7;
    int b = 8;
    std::vector<int> values;

    Defaulted() : values(128, 1)
    {
      ++constructions;
    }
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Defaulted);
  DECLARE_JSON_REQUIRED_FIELDS(Defaulted);
  DECLARE_JSON_OPTIONAL_FIELDS(Defaulted, a, b, values);

  struct Flags
  {
    uint32_t mode : 2;
    uint32_t count : 6;
  };

  DECLARE_JSON_TYPE(Flags);
  DECLARE_JSON_REQUIRED_FIELDS(Flags, mode, count);

  struct CustomBase
  {
    int value = 3;
  };

  void to_json(Json& j, const CustomBase& value)
  {
    j["wire_name"] = value.value;
  }

  void from_json(const Json& j, CustomBase& value)
  {
    value.value = j.at("wire_name").get<int>();
  }

  std::string schema_name([[maybe_unused]] const CustomBase* tag)
  {
    return "CustomBase";
  }

  void fill_json_schema(Json& schema, [[maybe_unused]] const CustomBase* tag)
  {
    schema = {
      {"type", "object"},
      {"properties", {{"wire_name", {{"type", "integer"}}}}},
      {"required", Json::array({"wire_name"})}};
  }

  struct CustomDerived : CustomBase
  {
    bool enabled = false;
  };

  DECLARE_JSON_TYPE_WITH_BASE(CustomDerived, CustomBase);
  DECLARE_JSON_REQUIRED_FIELDS(CustomDerived, enabled);
}

TEST_CASE("JSON macro frontends share direct IO and DOM contracts")
{
  for (
    const auto& input :
    {R"({"id":8,"transaction_id":null,"bytes":"AQID","labels":{}})",
     R"({"id":9,"retries":8,"transaction_id":"2.3","bytes":"","labels":{"a":"b"},"@nextLink":"/next"})"})
  {
    const auto json = Json::parse(input);
    const auto direct = ccf::json::read<Record>(input);
    const auto dom = json.get<Record>();
    CHECK(Json::parse(ccf::json::write(direct)) == json);
    CHECK(Json(direct) == Json(dom));
  }
  const auto added =
    ccf::json::read<NewRecord>(R"({"id":8,"message":"hello","future":true})");
  CHECK(added.priority == 7);
  CHECK(
    Json::parse(ccf::json::write(added)) ==
    Json{{"id", 8}, {"message", "hello"}, {"priority", 7}});
}

TEST_CASE("Direct JSON IO enforces field policies and buffer boundaries")
{
  for (const auto* input :
       {R"({"message":"hello"})",
        R"({"id":8,"message":null})",
        R"({"id":8,"message":"hello"}{})"})
  {
    CHECK_THROWS_AS(ccf::json::read<NewRecord>(input), ccf::JsonParseError);
  }
  const std::string storage = "1234";
  CHECK(ccf::json::read<int>(std::string_view(storage).substr(0, 2)) == 12);
  const std::array<char, 2> exact{'1', '2'};
  CHECK(
    ccf::json::read<int>(std::string_view(exact.data(), exact.size())) == 12);
  std::string reused = "previous output";
  ccf::json::write(NewRecord{8, "hello", 9}, reused);
  CHECK(Json::parse(reused).at("priority") == 9);
}

TEST_CASE("DOM conversions preserve updates and persisted KV encoding")
{
  NewRecord value{8, "hello", 9};
  Json output = {{"keep", true}};
  to_json(output, value);
  CHECK(output.at("keep") == true);
  Json{{"id", 9}, {"message", "updated"}}.get_to(value);
  CHECK(value.priority == 9);
  CHECK(value.message == "updated");
  const auto bytes =
    ccf::kv::serialisers::JsonSerialiser<NewRecord>::to_serialised(value);
  CHECK(std::string(bytes.begin(), bytes.end()) == Json(value).dump());
}

TEST_CASE("Macro schema generation preserves required and nullable fields")
{
  const auto schema = ccf::ds::json::build_schema<Record>();
  const auto& required = schema.at("required");
  CHECK(
    std::find(required.begin(), required.end(), "transaction_id") !=
    required.end());
  CHECK(schema.at("properties").contains("@nextLink"));
  CHECK(schema.at("properties").contains("bytes"));
  CHECK_FALSE(schema.at("properties").contains("next_link"));
}

TEST_CASE("DOM serialization constructs optional defaults once per owner")
{
  const Defaulted value{};
  Defaulted::constructions = 0;
  CHECK(Json(value) == Json::object());
  CHECK(Defaulted::constructions == 1);
}

TEST_CASE("Legacy custom shapes remain valid on the direct API")
{
  const Flags flags{2, 17};
  const auto decoded = ccf::json::read<Flags>(ccf::json::write(flags));
  CHECK(decoded.mode == 2);
  CHECK(decoded.count == 17);
  const CustomDerived custom{};
  const auto bytes = ccf::json::write(custom);
  CHECK(Json::parse(bytes) == Json{{"wire_name", 3}, {"enabled", false}});
  CHECK(ccf::json::read<CustomDerived>(bytes).value == 3);
  using NumericMap = std::map<int, std::string>;
  const NumericMap numeric_keys{{7, "seven"}};
  const auto map_bytes = ccf::json::write(numeric_keys);
  CHECK(Json::parse(map_bytes) == Json(numeric_keys));
  CHECK(ccf::json::read<NumericMap>(map_bytes) == numeric_keys);
}

TEST_CASE("Declared enum writers reject unmapped values at every nesting level")
{
  CHECK(ccf::json::write(Mode::Active) == R"("active")");
  CHECK(ccf::json::read<Mode>(R"("retired")") == Mode::Retired);
  CHECK_THROWS_AS(ccf::json::read<Mode>(R"("unknown")"), ccf::JsonParseError);
  for (const auto invalid : {Mode::Unmapped, static_cast<Mode>(99)})
  {
    CHECK_THROWS(Json(invalid));
    CHECK_THROWS(ccf::json::write(invalid));
    CHECK_THROWS(Json(WithMode{invalid}));
    CHECK_THROWS(ccf::json::write(WithMode{invalid}));
    CHECK_THROWS(ccf::json::write(std::vector<Mode>{Mode::Active, invalid}));
    CHECK_THROWS(
      ccf::json::write(std::map<std::string, Mode>{{"mode", invalid}}));
  }
}

TEST_CASE("Direct IO does not invoke DOM conversion hooks")
{
  CHECK_THROWS(Json(NativeOnly{}));
  CHECK_THROWS(Json{{"id", 8}}.get<NativeOnly>());
  CHECK(ccf::json::write(NativeOnly{}) == R"({"id":7})");
  CHECK(ccf::json::read<NativeOnly>(R"({"id":8})").id == 8);
}

TEST_CASE("Direct writers escape all JSON control characters")
{
  std::string controls;
  for (char c = 0; c < ' '; ++c)
  {
    controls.push_back(c);
  }
  for (const auto& text : {controls, std::string(128, 'x') + controls})
  {
    CHECK(Json::parse(ccf::json::write(text)) == text);
  }
}

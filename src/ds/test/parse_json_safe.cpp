// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
//
// Tests for ccf::parse_json_safe - the depth-bounded JSON parse chokepoint.
// parse_json_safe wraps nlohmann::json::parse with the library's
// parser_callback_t and aborts the parse before any DOM node is materialised
// once an object_start or array_start is reached at the configured maximum
// depth (default: ccf::MAX_JSON_NESTING_DEPTH, overridable per call site).

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/ds/json.h"

#include <doctest/doctest.h>
#include <string>

namespace
{
  // Builds {"a":{"a":...{"a":null}...}} of the requested nesting depth.
  // Examples: nest_obj(1) -> {"a":null}
  //           nest_obj(3) -> {"a":{"a":{"a":null}}}
  std::string nest_obj(size_t depth)
  {
    std::string s;
    s.reserve(depth * 6 + 4);
    for (size_t i = 0; i < depth; ++i)
    {
      s.append("{\"a\":");
    }
    s.append("null");
    for (size_t i = 0; i < depth; ++i)
    {
      s.push_back('}');
    }
    return s;
  }

  // Builds [[...[null]...]] of the requested nesting depth.
  // Examples: nest_arr(1) -> [null]
  //           nest_arr(3) -> [[[null]]]
  std::string nest_arr(size_t depth)
  {
    std::string s;
    s.reserve(depth * 2 + 4);
    for (size_t i = 0; i < depth; ++i)
    {
      s.push_back('[');
    }
    s.append("null");
    for (size_t i = 0; i < depth; ++i)
    {
      s.push_back(']');
    }
    return s;
  }

  // Far above any plausible legitimate payload.
  constexpr size_t kAttackDepth = 200'000;
  constexpr size_t kAtLimit = ccf::MAX_JSON_NESTING_DEPTH;
}

TEST_CASE("parse_json_safe rejects deeply nested objects far past the limit")
{
  // kAttackDepth (200 000) is well past MAX_JSON_NESTING_DEPTH and so must
  // be rejected long before any DOM is built.
  const auto body = nest_obj(kAttackDepth);
  CHECK_THROWS_AS(ccf::parse_json_safe(body), ccf::JsonTooDeep);
}

TEST_CASE("parse_json_safe rejects deeply nested arrays far past the limit")
{
  const auto body = nest_arr(kAttackDepth);
  CHECK_THROWS_AS(ccf::parse_json_safe(body), ccf::JsonTooDeep);
}

TEST_CASE("parse_json_safe rejects objects one level above the limit")
{
  // kAtLimit + 1 is the minimal rejection case: proves the boundary is
  // strictly "<= MAX_JSON_NESTING_DEPTH accepted, > rejected".
  const auto body = nest_obj(kAtLimit + 1);
  CHECK_THROWS_AS(ccf::parse_json_safe(body), ccf::JsonTooDeep);
}

TEST_CASE("parse_json_safe rejects arrays one level above the limit")
{
  const auto body = nest_arr(kAtLimit + 1);
  CHECK_THROWS_AS(ccf::parse_json_safe(body), ccf::JsonTooDeep);
}

TEST_CASE("parse_json_safe accepts objects exactly at the limit")
{
  // Exactly MAX_JSON_NESTING_DEPTH must round-trip cleanly: the bound
  // is inclusive so the maximum legitimate payload is not collateral damage.
  const auto body = nest_obj(kAtLimit);
  nlohmann::json j;
  CHECK_NOTHROW(j = ccf::parse_json_safe(body));
  CHECK(j.is_object());
}

TEST_CASE("parse_json_safe accepts arrays exactly at the limit")
{
  const auto body = nest_arr(kAtLimit);
  nlohmann::json j;
  CHECK_NOTHROW(j = ccf::parse_json_safe(body));
  CHECK(j.is_array());
}

TEST_CASE("parse_json_safe leaves shallow well-formed input unchanged")
{
  const auto body = std::string(R"({"k":[1,2,3],"v":{"x":true}})");
  nlohmann::json j;
  CHECK_NOTHROW(j = ccf::parse_json_safe(body));
  CHECK(j["k"].size() == 3);
  CHECK(j["v"]["x"] == true);
}

TEST_CASE("parse_json_safe propagates ordinary syntax errors as parse_error")
{
  // The callback only adds a depth check; ordinary parse errors still
  // surface as nlohmann::json::parse_error, NOT as JsonTooDeep.
  const auto body = std::string("{not json");
  CHECK_THROWS_AS(ccf::parse_json_safe(body), nlohmann::json::parse_error);
}

TEST_CASE("parse_json_safe iterator overload enforces the same limit")
{
  const auto body = nest_obj(kAttackDepth);
  CHECK_THROWS_AS(
    ccf::parse_json_safe(body.begin(), body.end()), ccf::JsonTooDeep);

  const auto shallow = std::string(R"({"a":1})");
  nlohmann::json j;
  CHECK_NOTHROW(j = ccf::parse_json_safe(shallow.begin(), shallow.end()));
  CHECK(j["a"] == 1);
}

TEST_CASE("JsonTooDeep is catchable as ccf::JsonParseError")
{
  // Frontend top-level catch in src/node/rpc/frontend.h relies on this
  // hierarchy to convert the failure into HTTP 400 InvalidInput.
  const auto body = nest_obj(kAttackDepth);
  CHECK_THROWS_AS(ccf::parse_json_safe(body), ccf::JsonParseError);
}

TEST_CASE("parse_json_safe honours a caller-supplied max_depth override")
{
  // A caller-supplied limit must take precedence over the default, both for
  // tightening (reject something the default would accept) and loosening
  // (accept something the default would reject) the bound.
  constexpr size_t kCustomLimit = 8;

  // Tighten: depth above kCustomLimit but well within the default must now
  // be rejected when the caller passes kCustomLimit.
  const auto tight_reject = nest_obj(kCustomLimit + 1);
  CHECK_THROWS_AS(
    ccf::parse_json_safe(tight_reject, kCustomLimit), ccf::JsonTooDeep);

  // Tighten boundary: exactly kCustomLimit must still be accepted when the
  // caller passes kCustomLimit, mirroring the inclusive default boundary.
  const auto tight_accept = nest_obj(kCustomLimit);
  nlohmann::json j;
  CHECK_NOTHROW(j = ccf::parse_json_safe(tight_accept, kCustomLimit));
  CHECK(j.is_object());

  // Loosen: depth above the default but within an explicit larger limit must
  // be accepted, proving the override is not just an upper bound on the
  // default.
  constexpr size_t kLooseLimit = ccf::MAX_JSON_NESTING_DEPTH + 16;
  const auto loose_accept = nest_obj(ccf::MAX_JSON_NESTING_DEPTH + 8);
  CHECK_NOTHROW(j = ccf::parse_json_safe(loose_accept, kLooseLimit));
  CHECK(j.is_object());
}

TEST_CASE("parse_json_safe iterator overload honours max_depth override")
{
  constexpr size_t kCustomLimit = 4;
  const auto body = nest_arr(kCustomLimit + 1);
  CHECK_THROWS_AS(
    ccf::parse_json_safe(body.begin(), body.end(), kCustomLimit),
    ccf::JsonTooDeep);

  const auto shallow = nest_arr(kCustomLimit);
  nlohmann::json j;
  CHECK_NOTHROW(
    j = ccf::parse_json_safe(shallow.begin(), shallow.end(), kCustomLimit));
  CHECK(j.is_array());
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/msgpack_adaptor_nlohmann.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

template <typename T>
T msgpack_roundtrip(const T& t)
{
  // Serialize
  msgpack::sbuffer sb;
  msgpack::pack(sb, t);

  // Deserialize
  msgpack::object_handle obj;
  msgpack::unpack(obj, sb.data(), sb.size(), 0);

  return obj->as<T>();
}

TEST_CASE("nlohmann::json")
{
  using namespace nlohmann;

  json j_null = nullptr;
  {
    const auto converted = msgpack_roundtrip(j_null);
    CHECK(j_null == converted);
  }

  json j_int = 42;
  {
    const auto converted = msgpack_roundtrip(j_int);
    CHECK(j_int == converted);
  }

  json j_float = 3.14f;
  {
    const auto converted = msgpack_roundtrip(j_float);
    CHECK(j_float == converted);
  }

  json j_string = "hello world";
  {
    const auto converted = msgpack_roundtrip(j_string);
    CHECK(j_string == converted);
  }

  json j_array = json::array();
  j_array.push_back(j_null);
  j_array.push_back(j_int);
  j_array.push_back(j_float);
  j_array.push_back(j_string);
  {
    const auto converted = msgpack_roundtrip(j_array);
    CHECK(j_array == converted);
  }

  json j_object = json::object();
  j_object["A"] = j_array;
  j_object["saluton mondo"] = j_string;
  {
    const auto converted = msgpack_roundtrip(j_object);
    CHECK(j_object == converted);
  }
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "msgpack/encode.h"

#include <nlohmann/json.hpp>

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <cstdint>
#include <picobench/picobench.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <string>
#include <string_view>
#include <vector>

namespace
{
  constexpr uint64_t uint_value = 1234567890ULL;
  constexpr int64_t int_value = -123456789LL;
  constexpr double float_value = 12.5;
  constexpr std::string_view string_value = "hello msgpack";
  constexpr int64_t nested_map_value = 42;
  constexpr int64_t array_value = -7;

  template <class T>
  inline void do_not_optimize(const T& value)
  {
    asm volatile("" : : "r,m"(value) : "memory");
  }

  inline void clobber_memory()
  {
    asm volatile("" : : : "memory");
  }

  nlohmann::json make_json_object()
  {
    nlohmann::json j = nlohmann::json::object();
    j["nil"] = nullptr;
    j["bool"] = true;
    j["uint"] = uint_value;
    j["int"] = int_value;
    j["float"] = float_value;
    j["string"] = string_value;
    j["map"] = nlohmann::json{{"value", nested_map_value}};
    j["array"] = nlohmann::json::array({array_value});
    return j;
  }

  void write_msgpack_object(std::vector<uint8_t>& out)
  {
    ccf::msgpack::write_map_header(out, 8);

    ccf::msgpack::write_str(out, "nil");
    ccf::msgpack::write_nil(out);

    ccf::msgpack::write_str(out, "bool");
    ccf::msgpack::write_bool(out, true);

    ccf::msgpack::write_str(out, "uint");
    ccf::msgpack::write_uint(out, uint_value);

    ccf::msgpack::write_str(out, "int");
    ccf::msgpack::write_int(out, int_value);

    ccf::msgpack::write_str(out, "float");
    ccf::msgpack::write_float(out, float_value);

    ccf::msgpack::write_str(out, "string");
    ccf::msgpack::write_str(out, string_value);

    ccf::msgpack::write_str(out, "map");
    ccf::msgpack::write_map_header(out, 1);
    ccf::msgpack::write_str(out, "value");
    ccf::msgpack::write_int(out, nested_map_value);

    ccf::msgpack::write_str(out, "array");
    ccf::msgpack::write_array_header(out, 1);
    ccf::msgpack::write_int(out, array_value);
  }

  void write_rapidjson_object(rapidjson::Writer<rapidjson::StringBuffer>& w)
  {
    w.StartObject();

    w.Key("nil");
    w.Null();

    w.Key("bool");
    w.Bool(true);

    w.Key("uint");
    w.Uint64(uint_value);

    w.Key("int");
    w.Int64(int_value);

    w.Key("float");
    w.Double(float_value);

    w.Key("string");
    w.String(
      string_value.data(),
      static_cast<rapidjson::SizeType>(string_value.size()));

    w.Key("map");
    w.StartObject();
    w.Key("value");
    w.Int64(nested_map_value);
    w.EndObject();

    w.Key("array");
    w.StartArray();
    w.Int64(array_value);
    w.EndArray();

    w.EndObject();
  }

  static void json_dump(picobench::state& s)
  {
    clobber_memory();
    picobench::scope scope(s);

    for (int i = 0; i < s.iterations(); ++i)
    {
      const auto j = make_json_object();
      const auto dumped = j.dump();
      do_not_optimize(dumped);
      clobber_memory();
    }
  }

  static void msgpack_encode(picobench::state& s)
  {
    clobber_memory();
    picobench::scope scope(s);

    for (int i = 0; i < s.iterations(); ++i)
    {
      std::vector<uint8_t> out;
      write_msgpack_object(out);
      do_not_optimize(out);
      clobber_memory();
    }
  }

  static void rapidjson_write(picobench::state& s)
  {
    clobber_memory();
    picobench::scope scope(s);

    for (int i = 0; i < s.iterations(); ++i)
    {
      rapidjson::StringBuffer buffer;
      rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
      write_rapidjson_object(writer);
      do_not_optimize(buffer);
      clobber_memory();
    }
  }
}

const std::vector<int> sizes = {100, 1'000, 10'000};

PICOBENCH_SUITE("msgpack serialise");
PICOBENCH(json_dump).iterations(sizes).baseline();
PICOBENCH(rapidjson_write).iterations(sizes);
PICOBENCH(msgpack_encode).iterations(sizes);

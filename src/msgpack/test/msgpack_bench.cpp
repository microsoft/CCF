// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "msgpack/encode.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include <picobench/picobench.hpp>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
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
  constexpr size_t reserved_capacity = 128;

  template <class T>
  inline void do_not_optimize(const T& value)
  {
    asm volatile("" : : "r,m"(value) : "memory");
  }

  inline void clobber_memory()
  {
    asm volatile("" : : : "memory");
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

  void verify_reserved_capacity()
  {
    std::vector<uint8_t> out;
    write_msgpack_object(out);
    if (out.size() > reserved_capacity)
    {
      throw std::logic_error("reserved capacity no longer covers benchmark");
    }
  }

  void encode_fresh(picobench::state& state)
  {
    verify_reserved_capacity();

    clobber_memory();
    picobench::scope scope(state);

    for (int i = 0; i < state.iterations(); ++i)
    {
      std::vector<uint8_t> out;
      write_msgpack_object(out);
      do_not_optimize(out);
      clobber_memory();
    }
  }

  void encode_reserved(picobench::state& state)
  {
    verify_reserved_capacity();

    clobber_memory();
    picobench::scope scope(state);

    for (int i = 0; i < state.iterations(); ++i)
    {
      std::vector<uint8_t> out;
      out.reserve(reserved_capacity);
      write_msgpack_object(out);
      do_not_optimize(out);
      clobber_memory();
    }
  }

  void encode_reused(picobench::state& state)
  {
    verify_reserved_capacity();

    std::vector<uint8_t> out;
    out.reserve(reserved_capacity);

    clobber_memory();
    picobench::scope scope(state);

    for (int i = 0; i < state.iterations(); ++i)
    {
      out.clear();
      write_msgpack_object(out);
      do_not_optimize(out);
      clobber_memory();
    }
  }
}

const std::vector<int> sizes = {100, 1'000, 10'000};

PICOBENCH_SUITE("msgpack serialise");
PICOBENCH(encode_fresh).iterations(sizes).baseline();
PICOBENCH(encode_reserved).iterations(sizes);
PICOBENCH(encode_reused).iterations(sizes);

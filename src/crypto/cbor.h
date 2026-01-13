// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstdint>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <variant>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ccf::cbor
{
  struct ValueImpl;
  using Value = std::unique_ptr<ValueImpl>;

  using Signed = int64_t;
  using Bytes = std::span<const uint8_t>;
  using String = std::string_view;
  using Simple = uint8_t;

  // https://www.iana.org/assignments/cbor-simple-values/cbor-simple-values.xhtml.
  //
  // To be filled further on demand, currently only those to be (likely) used.
  enum SimpleValue : uint8_t
  {
    False = 20,
    True = 21,
    Null = 22,
    Undefined = 23,
  };

  struct Array
  {
    std::vector<Value> items;
  };

  struct Map
  {
    std::vector<std::pair<Value, Value>> items;
  };

  struct Tagged
  {
    uint64_t tag{0};
    Value item{nullptr};
  };

  using Type = std::variant<Signed, Bytes, String, Array, Map, Tagged, Simple>;

  using CBORDecodeError = std::runtime_error;

  struct ValueImpl
  {
    ValueImpl(Type value_) : value(std::move(value_)) {}
    Type value;

    [[nodiscard]] const Value& array_at(size_t index) const;
    [[nodiscard]] const Value& map_at(const Value& key) const;
    [[nodiscard]] const Value& tag_at(uint64_t tag) const;
    [[nodiscard]] Signed as_signed() const;
    [[nodiscard]] Bytes as_bytes() const;
    [[nodiscard]] String as_string() const;
    [[nodiscard]] Simple as_simple() const;
    [[nodiscard]] size_t size() const;
  };

  Value make_signed(int64_t value);
  Value make_string(std::string_view data);
  Value make_bytes(std::span<const uint8_t> data);

  Value parse(std::span<const uint8_t> raw);
  std::string to_string(const Value& value);
  bool simple_to_boolean(const Simple& value);

  decltype(auto) rethrow_with_msg(auto&& f, std::string_view msg = {})
  {
    try
    {
      return f();
    }
    catch (const CBORDecodeError& err)
    {
      if (!msg.empty())
      {
        throw CBORDecodeError(fmt::format("{}: {}", err.what(), msg));
      }
      throw err;
    }
  }
} // namespace ccf::cbor
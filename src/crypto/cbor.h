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

namespace ccf::cbor
{
  struct WrappedValue;
  using Value = std::unique_ptr<WrappedValue>;

  using Unsigned = uint64_t;
  using Signed = int64_t;
  using Bytes = std::span<const uint8_t>;
  using String = std::string_view;
  using Simple = uint8_t;

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

  using Type =
    std::variant<Unsigned, Signed, Bytes, String, Array, Map, Tagged, Simple>;

  using CBORDecodeError = std::runtime_error;

  struct WrappedValue
  {
    WrappedValue(Type value_) : value(std::move(value_)) {}
    Type value;

    const Value& array_at(size_t index, std::string_view context = {}) const;
    const Value& map_at(const Value& key, std::string_view context = {}) const;
    const Value& tag_at(
      const uint64_t tag, std::string_view context = {}) const;
    Unsigned as_unsigned(std::string_view context = {}) const;
    Signed as_signed(std::string_view context = {}) const;
    Bytes as_bytes(std::string_view context = {}) const;
    String as_string(std::string_view context = {}) const;
    Simple as_simple(std::string_view context = {}) const;
    size_t size() const;
  };

  Value make_unsigned(uint64_t value);
  Value make_signed(int64_t value);
  Value make_string(std::string_view data);

  Value parse_wrapped(
    std::span<const uint8_t> raw, std::string_view context = {});
  std::string print_value(const Value& value, size_t indent = 0);
} // namespace ccf::cbor
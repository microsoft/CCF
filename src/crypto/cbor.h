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
  struct ValueImpl;
  using Value = std::unique_ptr<ValueImpl>;

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

  struct ValueImpl
  {
    ValueImpl(Type value_) : value(std::move(value_)) {}
    Type value;

    [[nodiscard]] const Value& array_at(
      size_t index, std::string_view context = {}) const;
    [[nodiscard]] const Value& map_at(
      const Value& key, std::string_view context = {}) const;
    [[nodiscard]] const Value& tag_at(
      uint64_t tag, std::string_view context = {}) const;
    [[nodiscard]] Unsigned as_unsigned(std::string_view context = {}) const;
    [[nodiscard]] Signed as_signed(std::string_view context = {}) const;
    [[nodiscard]] Bytes as_bytes(std::string_view context = {}) const;
    [[nodiscard]] String as_string(std::string_view context = {}) const;
    [[nodiscard]] Simple as_simple(std::string_view context = {}) const;
    [[nodiscard]] size_t size() const;
  };

  Value make_unsigned(uint64_t value);
  Value make_signed(int64_t value);
  Value make_string(std::string_view data);

  Value parse_value(
    std::span<const uint8_t> raw, std::string_view context = {});
  std::string print_value(const Value& value, size_t indent = 0);
} // namespace ccf::cbor
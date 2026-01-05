// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/cbor.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

extern "C"
{
#include "evercbor/CBORNondet.h"
}

using namespace ccf::cbor;

namespace
{
  Value consume(cbor_nondet_t cbor);

  // Helper to wrap operations with context-aware error messages
  template <typename F>
  decltype(auto) with_context(
    std::string_view context, std::string_view operation, const F& func)
  {
    try
    {
      return func();
    }
    catch (const CBORDecodeError& e)
    {
      if (!context.empty())
      {
        throw CBORDecodeError(
          fmt::format("Failed to {} {}: {}", operation, context, e.what()));
      }
      throw;
    }
  }

  void print_indent(std::ostringstream& os, size_t indent)
  {
    for (size_t i = 0; i < indent; ++i)
    {
      os << "  ";
    }
  }

  Value consume_unsigned(cbor_nondet_t cbor)
  {
    Unsigned value{0};
    if (!cbor_nondet_read_uint64(cbor, &value))
    {
      throw CBORDecodeError("Failed to consume unsigned value");
    }
    return std::make_unique<ValueImpl>(value);
  }

  Value consume_signed(cbor_nondet_t cbor)
  {
    Signed value{0};
    if (!cbor_nondet_read_int64(cbor, &value))
    {
      throw CBORDecodeError("Failed to decode signed value");
    }
    return std::make_unique<ValueImpl>(value);
  }

  Value consume_byte_string(cbor_nondet_t cbor)
  {
    uint8_t* data = nullptr;
    uint64_t length = 0;
    if (!cbor_nondet_get_byte_string(cbor, &data, &length))
    {
      throw CBORDecodeError("Failed to decode byte string");
    }
    Bytes value{data, static_cast<size_t>(length)};
    return std::make_unique<ValueImpl>(value);
  }

  Value consume_text_string(cbor_nondet_t cbor)
  {
    uint8_t* data = nullptr;
    uint64_t length = 0;
    if (!cbor_nondet_get_text_string(cbor, &data, &length))
    {
      throw CBORDecodeError("Failed to decode text string");
    }
    String value{
      reinterpret_cast<const char*>(data), static_cast<size_t>(length)};
    return std::make_unique<ValueImpl>(value);
  }

  Value consume_array(cbor_nondet_t cbor)
  {
    cbor_nondet_array_iterator_t iter;
    if (!cbor_nondet_array_iterator_start(cbor, &iter))
    {
      throw CBORDecodeError("Failed to start array iterator");
    }

    Array array;
    while (!cbor_nondet_array_iterator_is_empty(iter))
    {
      cbor_nondet_t item;
      if (!cbor_nondet_array_iterator_next(&iter, &item))
      {
        throw CBORDecodeError("Failed to get next array item");
      }
      array.items.push_back(consume(item));
    }
    return std::make_unique<ValueImpl>(std::move(array));
  }

  Value consume_map(cbor_nondet_t cbor)
  {
    cbor_map_iterator iter;
    if (!cbor_nondet_map_iterator_start(cbor, &iter))
    {
      throw CBORDecodeError("Failed to start map iterator");
    }

    Map map;
    while (!cbor_nondet_map_iterator_is_empty(iter))
    {
      cbor_raw key_raw;
      cbor_raw value_raw;
      if (!cbor_nondet_map_iterator_next(&iter, &key_raw, &value_raw))
      {
        throw CBORDecodeError("Failed to get next map entry");
      }
      map.items.emplace_back(consume(key_raw), consume(value_raw));
    }
    return std::make_unique<ValueImpl>(std::move(map));
  }

  Value consume_tagged(cbor_nondet_t cbor)
  {
    uint64_t tag = 0;
    cbor_nondet_t payload;
    if (!cbor_nondet_get_tagged(cbor, &payload, &tag))
    {
      throw CBORDecodeError("Failed to decode tagged value");
    }

    Tagged tagged;
    tagged.tag = tag;
    tagged.item = consume(payload);
    return std::make_unique<ValueImpl>(std::move(tagged));
  }

  Value consume_simple(cbor_nondet_t cbor)
  {
    // Return the raw simple value (single byte) and leave detailed
    // interpretation to the caller. EverCBOR does not yet support more granular
    // parsing, or floating point numbers with extra payload.
    Simple value{0};
    if (!cbor_nondet_read_simple_value(cbor, &value))
    {
      throw CBORDecodeError("Failed to decode simple value");
    }
    return std::make_unique<ValueImpl>(value);
  }

  Value consume(cbor_nondet_t cbor)
  {
    const auto mt = cbor_nondet_major_type(cbor);
    switch (mt)
    {
      case CBOR_MAJOR_TYPE_UINT64:
        return consume_unsigned(cbor);
      case CBOR_MAJOR_TYPE_NEG_INT64:
        return consume_signed(cbor);
      case CBOR_MAJOR_TYPE_BYTE_STRING:
        return consume_byte_string(cbor);
      case CBOR_MAJOR_TYPE_TEXT_STRING:
        return consume_text_string(cbor);
      case CBOR_MAJOR_TYPE_ARRAY:
        return consume_array(cbor);
      case CBOR_MAJOR_TYPE_MAP:
        return consume_map(cbor);
      case CBOR_MAJOR_TYPE_TAGGED:
        return consume_tagged(cbor);
      case CBOR_MAJOR_TYPE_SIMPLE_VALUE:
        return consume_simple(cbor);
      default:
        throw CBORDecodeError("Unknown CBOR major type");
    }
  }

  void print_value_impl(
    std::ostringstream& os, const Value& value, size_t indent)
  {
    if (!value)
    {
      print_indent(os, indent);
      os << "<null>" << std::endl;
      return;
    }

    std::visit(
      [&os, indent](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, Unsigned>)
        {
          print_indent(os, indent);
          os << "Unsigned: " << v << std::endl;
        }
        else if constexpr (std::is_same_v<T, Signed>)
        {
          print_indent(os, indent);
          os << "Signed: " << v << std::endl;
        }
        else if constexpr (std::is_same_v<T, Bytes>)
        {
          print_indent(os, indent);
          os << "Bytes[" << v.size() << "]: ";
          for (size_t i = 0; i < std::min(v.size(), size_t(16)); ++i)
          {
            os << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(v[i]);
          }
          if (v.size() > 16)
          {
            os << "...";
          }
          os << std::dec << std::endl;
        }
        else if constexpr (std::is_same_v<T, String>)
        {
          print_indent(os, indent);
          os << "String: \"" << v << "\"" << std::endl;
        }
        else if constexpr (std::is_same_v<T, Array>)
        {
          print_indent(os, indent);
          os << "Array[" << v.items.size() << "]:" << std::endl;
          for (const auto& item : v.items)
          {
            print_value_impl(os, item, indent + 1);
          }
        }
        else if constexpr (std::is_same_v<T, Map>)
        {
          print_indent(os, indent);
          os << "Map[" << v.items.size() << "]:" << std::endl;
          for (const auto& [key, val] : v.items)
          {
            print_indent(os, indent + 1);
            os << "Key:" << std::endl;
            print_value_impl(os, key, indent + 2);
            print_indent(os, indent + 1);
            os << "Value:" << std::endl;
            print_value_impl(os, val, indent + 2);
          }
        }
        else if constexpr (std::is_same_v<T, Tagged>)
        {
          print_indent(os, indent);
          os << "Tagged[" << v.tag << "]:" << std::endl;
          print_value_impl(os, v.item, indent + 1);
        }
        else if constexpr (std::is_same_v<T, Simple>)
        {
          print_indent(os, indent);
          os << "Simple: " << static_cast<int>(v) << std::endl;
        }
      },
      value->value);
  }

} // namespace

namespace ccf::cbor
{
  Value make_unsigned(uint64_t value)
  {
    return std::make_unique<ValueImpl>(value);
  }
  Value make_signed(int64_t value)
  {
    return std::make_unique<ValueImpl>(value);
  }
  Value make_string(std::string_view data)
  {
    return std::make_unique<ValueImpl>(data);
  }

  Value parse_value(std::span<const uint8_t> raw, std::string_view context)
  {
    return with_context(context, "parse", [&] {
      cbor_nondet_t cbor;
      const bool check_map_key_bound = false;
      const size_t map_key_bound = 0;
      auto* cbor_parse_input = const_cast<uint8_t*>(raw.data());
      size_t cbor_parse_size = raw.size();
      if (!cbor_nondet_parse(
            check_map_key_bound,
            map_key_bound,
            &cbor_parse_input,
            &cbor_parse_size,
            &cbor))
      {
        throw CBORDecodeError("Failed to parse top-level cbor");
      }

      return consume(cbor);
    });
  }

  std::string print_value(const Value& value, size_t indent)
  {
    std::ostringstream os;
    print_value_impl(os, value, indent);
    return os.str();
  }

  const Value& ValueImpl::array_at(size_t index, std::string_view context) const
  {
    return with_context(context, "access array element", [&]() -> const Value& {
      if (!std::holds_alternative<Array>(value))
      {
        throw CBORDecodeError("Not an array");
      }

      const auto& arr = std::get<Array>(value);
      if (index >= arr.items.size())
      {
        throw CBORDecodeError("Array index out of bounds");
      }

      return arr.items[index];
    });
  }

  const Value& ValueImpl::map_at(
    const Value& key, std::string_view context) const
  {
    return with_context(context, "access map key", [&]() -> const Value& {
      if (!std::holds_alternative<Map>(value))
      {
        throw CBORDecodeError("Not a map");
      }

      // Fail fast: Array, Map, Tagged are not supported as map keys in this
      // version, and probably shouldn't be in the future.
      std::visit(
        [](const auto& k) {
          using T = std::decay_t<decltype(k)>;
          if constexpr (
            std::is_same_v<T, Array> || std::is_same_v<T, Map> ||
            std::is_same_v<T, Tagged>)
          {
            throw CBORDecodeError(
              "Array, Map, and Tagged values cannot be used as map keys");
          }
        },
        key->value);

      const auto& map = std::get<Map>(value);
      for (const auto& [k, v] : map.items)
      {
        const bool match = std::visit(
          [](const auto& a, const auto& b) -> bool {
            using TA = std::decay_t<decltype(a)>;
            using TB = std::decay_t<decltype(b)>;

            if constexpr (!std::is_same_v<TA, TB>)
            {
              return false;
            }
            else if constexpr (
              std::is_same_v<TA, Unsigned> || std::is_same_v<TA, Signed>)
            {
              return a == b;
            }
            else if constexpr (
              std::is_same_v<TA, Bytes> || std::is_same_v<TA, String>)
            {
              return std::equal(a.begin(), a.end(), b.begin(), b.end());
            }
            else
            {
              return false;
            }
          },
          key->value,
          k->value);

        if (match)
        {
          return v;
        }
      }

      throw CBORDecodeError("Key not found in map");
    });
  }

  size_t ValueImpl::size() const
  {
    if (std::holds_alternative<Array>(value))
    {
      const auto& arr = std::get<Array>(value);
      return arr.items.size();
    }
    if (std::holds_alternative<Map>(value))
    {
      const auto& map = std::get<Map>(value);
      return map.items.size();
    }
    throw CBORDecodeError("Not a collection");
  }

  const Value& ValueImpl::tag_at(uint64_t tag, std::string_view context) const
  {
    return with_context(context, "extract tag", [&]() -> const Value& {
      if (!std::holds_alternative<Tagged>(value))
      {
        throw CBORDecodeError("Not a tagged value");
      }

      const auto& tagged = std::get<Tagged>(value);
      if (tagged.tag != tag)
      {
        throw CBORDecodeError("Tag does not match");
      }

      return tagged.item;
    });
  }

  Unsigned ValueImpl::as_unsigned(std::string_view context) const
  {
    return with_context(context, "convert to unsigned", [&] {
      if (!std::holds_alternative<Unsigned>(value))
      {
        throw CBORDecodeError("Not an unsigned value");
      }
      return std::get<Unsigned>(value);
    });
  }
  Signed ValueImpl::as_signed(std::string_view context) const
  {
    return with_context(context, "convert to signed", [&] {
      if (!std::holds_alternative<Signed>(value))
      {
        throw CBORDecodeError("Not a signed value");
      }
      return std::get<Signed>(value);
    });
  }
  Bytes ValueImpl::as_bytes(std::string_view context) const
  {
    return with_context(context, "convert to bytes", [&] {
      if (!std::holds_alternative<Bytes>(value))
      {
        throw CBORDecodeError("Not a bytes value");
      }
      return std::get<Bytes>(value);
    });
  }
  String ValueImpl::as_string(std::string_view context) const
  {
    return with_context(context, "convert to string", [&] {
      if (!std::holds_alternative<String>(value))
      {
        throw CBORDecodeError("Not a string value");
      }
      return std::get<String>(value);
    });
  }
  Simple ValueImpl::as_simple(std::string_view context) const
  {
    return with_context(context, "convert to simple", [&] {
      if (!std::holds_alternative<Simple>(value))
      {
        throw CBORDecodeError("Not a simple value");
      }
      return std::get<Simple>(value);
    });
  }
} // namespace ccf::cbor
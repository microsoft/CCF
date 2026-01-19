// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/cbor.h"

#include "ccf/ds/hex.h"

#include <algorithm>
#include <iomanip>
#include <list>
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
  /* Handy storage of 'cbor_raw's when recurively nesting objects. EverCBOR
   * collections work as pointers from one cbor_raw to another, with arrays
   * relying on space continuity, and that has to stay intact until calling
   * cbor_nondet_serialize. Therefore, the following choices have been made:
   *
   * - individual items stored in lists rather then collections to avoid
   * move-on-resize
   * - CBOR collections are made vectors for continuity, and only referenced
   * after filled up.
   */
  class CborRawArena
  {
  public:
    CborRawArena() = default;
    ~CborRawArena() = default;

    void push(cbor_raw&& single)
    {
      singles.push_back(single);
    }

    cbor_raw* single() const
    {
      return const_cast<cbor_raw*>(&singles.back());
    }

    void push(std::vector<cbor_raw>&& array)
    {
      arrays.push_back(array);
    }

    cbor_raw* array() const
    {
      return const_cast<cbor_raw*>(&arrays.back().front());
    }

    void push(std::vector<cbor_map_entry>&& map)
    {
      maps.push_back(map);
    }

    cbor_map_entry* map() const
    {
      return const_cast<cbor_map_entry*>(&maps.back().front());
    }

    // No copy
    CborRawArena(const CborRawArena&) = delete;
    CborRawArena& operator=(const CborRawArena&) = delete;

    // No move
    CborRawArena(CborRawArena&&) = delete;
    CborRawArena& operator=(CborRawArena&&) = delete;

  private:
    std::list<cbor_raw> singles;
    std::list<std::vector<cbor_raw>> arrays;
    std::list<std::vector<cbor_map_entry>> maps;
  };
  Value consume(cbor_nondet_t cbor);

  void print_indent(std::ostringstream& os, size_t indent)
  {
    for (size_t i = 0; i < indent; ++i)
    {
      os << "  ";
    }
  }

  Value consume_signed(cbor_nondet_t cbor)
  {
    Signed value{0};
    if (!cbor_nondet_read_int64(cbor, &value))
    {
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to decode signed value");
    }
    return std::make_unique<ValueImpl>(value);
  }

  Value consume_byte_string(cbor_nondet_t cbor)
  {
    uint8_t* data = nullptr;
    uint64_t length = 0;
    if (!cbor_nondet_get_byte_string(cbor, &data, &length))
    {
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to decode byte string");
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
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to decode text string");
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
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to start array iterator");
    }

    Array array;
    while (!cbor_nondet_array_iterator_is_empty(iter))
    {
      cbor_nondet_t item;
      if (!cbor_nondet_array_iterator_next(&iter, &item))
      {
        throw CBORDecodeError(
          Error::DECODE_FAILED, "Failed to get next array item");
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
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to start map iterator");
    }

    Map map;
    while (!cbor_nondet_map_iterator_is_empty(iter))
    {
      cbor_raw key_raw;
      cbor_raw value_raw;
      if (!cbor_nondet_map_iterator_next(&iter, &key_raw, &value_raw))
      {
        throw CBORDecodeError(
          Error::DECODE_FAILED, "Failed to get next map entry");
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
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to decode tagged value");
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
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to decode simple value");
    }
    return std::make_unique<ValueImpl>(value);
  }

  Value consume(cbor_nondet_t cbor)
  {
    const auto mt = cbor_nondet_major_type(cbor);
    switch (mt)
    {
      case CBOR_MAJOR_TYPE_UINT64:
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
        throw CBORDecodeError(Error::DECODE_FAILED, "Unknown CBOR major type");
    }
  }

  std::string format_simple(const Simple& v)
  {
    const auto casted = static_cast<int>(v);
    switch (casted)
    {
      case SimpleValue::False:
        return "Simple: False";
      case SimpleValue::True:
        return "Simple: True";
      case SimpleValue::Null:
        return "Simple: Null";
      case SimpleValue::Undefined:
        return "Simple: Undefined";
      default:
        return "Simple: " + std::to_string(casted);
    }
  }

  cbor_raw to_raw_cbor(const Value& value, CborRawArena& arena);

  cbor_raw to_raw_signed(const Signed& v)
  {
    return cbor_nondet_mk_int64(v);
  }

  cbor_raw to_raw_string(const String& v)
  {
    cbor_raw result;
    if (!cbor_nondet_mk_text_string(
          reinterpret_cast<uint8_t*>(const_cast<char*>(v.data())),
          v.size(),
          &result))
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED, fmt::format("Encoding text string {} failed", v));
    }
    return result;
  }

  cbor_raw to_raw_bytes(const Bytes& v)
  {
    cbor_raw result;
    if (!cbor_nondet_mk_byte_string(
          const_cast<uint8_t*>(v.data()), v.size(), &result))
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED,
        fmt::format("Encoding bytes string {} failed", ccf::ds::to_hex(v)));
    }
    return result;
  }

  cbor_raw to_raw_simple(const Simple& v)
  {
    cbor_raw result;
    if (!cbor_nondet_mk_simple_value(v, &result))
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED,
        fmt::format("Encoding simple value {} failed", format_simple(v)));
    }
    return result;
  }

  cbor_raw to_raw_tagged(const Tagged& v, CborRawArena& arena)
  {
    cbor_raw result;
    arena.push(to_raw_cbor(v.item, arena));
    if (!cbor_nondet_mk_tagged(v.tag, arena.single(), &result))
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED, fmt::format("Encoding tag {} failed", v.tag));
    }

    return result;
  }

  cbor_raw to_raw_array(const Array& v, CborRawArena& arena)
  {
    cbor_raw result;
    std::vector<cbor_raw> items;
    for (const auto& item : v.items)
    {
      items.push_back(to_raw_cbor(item, arena));
    }

    size_t arr_size = items.size();

    // A workaround to encode an enpty array by passing a fake ptr with size=0.
    if (items.empty())
    {
      items.push_back(cbor_raw{});
    }

    arena.push(std::move(items));
    if (!cbor_nondet_mk_array(arena.array(), arr_size, &result))
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED,
        fmt::format("Encoding array of size {} failed", arr_size));
    }

    return result;
  }

  cbor_raw to_raw_map(const Map& v, CborRawArena& arena)
  {
    cbor_raw result;

    std::vector<cbor_map_entry> entries;
    for (const auto& [key, value] : v.items)
    {
      auto cbor_key = to_raw_cbor(key, arena);
      auto cbor_value = to_raw_cbor(value, arena);
      entries.push_back(cbor_nondet_mk_map_entry(cbor_key, cbor_value));
    }

    size_t map_size = entries.size();

    // A workaround to encode an enpty map by passing a fake ptr with size=0.
    if (entries.empty())
    {
      entries.push_back(cbor_map_entry{});
    }

    arena.push(std::move(entries));
    if (!cbor_nondet_mk_map(arena.map(), map_size, &result))
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED,
        fmt::format("Encoding map of size {} failed", map_size));
    }

    return result;
  }

  cbor_raw to_raw_cbor(const Value& value, CborRawArena& arena)
  {
    return std::visit(
      [&](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, Signed>)
        {
          return to_raw_signed(v);
        }
        if constexpr (std::is_same_v<T, String>)
        {
          return to_raw_string(v);
        }
        if constexpr (std::is_same_v<T, Bytes>)
        {
          return to_raw_bytes(v);
        }
        if constexpr (std::is_same_v<T, Simple>)
        {
          return to_raw_simple(v);
        }
        if constexpr (std::is_same_v<T, Tagged>)
        {
          return to_raw_tagged(v, arena);
        }
        if constexpr (std::is_same_v<T, Array>)
        {
          return to_raw_array(v, arena);
        }
        if constexpr (std::is_same_v<T, Map>)
        {
          return to_raw_map(v, arena);
        }
      },
      value->value);
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
        if constexpr (std::is_same_v<T, Signed>)
        {
          print_indent(os, indent);
          os << "Signed: " << v << std::endl;
        }
        else if constexpr (std::is_same_v<T, Bytes>)
        {
          print_indent(os, indent);
          os << "Bytes[" << v.size() << "]:";
          if (!v.empty())
          {
            os << " ";
          }
          os << ccf::ds::to_hex(v) << std::endl;
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
          os << format_simple(v) << std::endl;
        }
      },
      value->value);
  }
} // namespace

namespace ccf::cbor
{
  CBOREncodeError::CBOREncodeError(Error err, const std::string& what) :
    std::runtime_error(what),
    error(err)
  {}

  Error CBOREncodeError::error_code() const
  {
    return error;
  }

  CBORDecodeError::CBORDecodeError(Error err, const std::string& what) :
    std::runtime_error(what),
    error(err)
  {}

  Error CBORDecodeError::error_code() const
  {
    return error;
  }

  Value make_signed(int64_t value)
  {
    return std::make_unique<ValueImpl>(value);
  }

  Value make_string(std::string_view data)
  {
    return std::make_unique<ValueImpl>(data);
  }

  Value make_bytes(std::span<const uint8_t> data)
  {
    return std::make_unique<ValueImpl>(data);
  }

  Value parse(std::span<const uint8_t> raw)
  {
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
      throw CBORDecodeError(
        Error::DECODE_FAILED, "Failed to parse top-level cbor");
    }

    return consume(cbor);
  }

  std::vector<uint8_t> serialize(const Value& value)
  {
    CborRawArena arena{};
    auto raw = to_raw_cbor(value, arena);
    const auto expected_size =
      cbor_nondet_size(raw, std::numeric_limits<size_t>::max());

    std::vector<uint8_t> result(expected_size);

    const auto bytes_written =
      cbor_nondet_serialize(raw, result.data(), expected_size);
    if (bytes_written != expected_size)
    {
      throw CBOREncodeError(
        Error::ENCODE_FAILED,
        fmt::format(
          "Encoded CBOR of size {} when expected {}",
          bytes_written,
          expected_size));
    }

    return result;
  }

  std::string to_string(const Value& value)
  {
    std::ostringstream os;
    constexpr size_t initial_indent{0};
    print_value_impl(os, value, initial_indent);
    auto as_string = os.str();
    if (!as_string.empty() && as_string.back() == '\n')
    {
      as_string.pop_back();
    }
    return as_string;
  }

  bool simple_to_boolean(const Simple& value)
  {
    switch (value)
    {
      case SimpleValue::False:
        return false;
      case SimpleValue::True:
        return true;
      default:
        throw CBORDecodeError(
          Error::TYPE_MISMATCH, "Simple value cannot be matched to boolean");
    }
  }

  const Value& ValueImpl::array_at(size_t index) const
  {
    if (!std::holds_alternative<Array>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not an array");
    }

    const auto& arr = std::get<Array>(value);
    if (index >= arr.items.size())
    {
      throw CBORDecodeError(Error::OUT_OF_BOUND, "Array index out of bounds");
    }

    return arr.items[index];
  }

  const Value& ValueImpl::map_at(const Value& key) const
  {
    if (!std::holds_alternative<Map>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a map");
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
            Error::TYPE_MISMATCH,
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
          else if constexpr (std::is_same_v<TA, Signed>)
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

    throw CBORDecodeError(Error::KEY_NOT_FOUND, "Key not found in map");
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
    throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a collection");
  }

  const Value& ValueImpl::tag_at(uint64_t tag) const
  {
    if (!std::holds_alternative<Tagged>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a tagged value");
    }

    const auto& tagged = std::get<Tagged>(value);
    if (tagged.tag != tag)
    {
      throw CBORDecodeError(Error::KEY_NOT_FOUND, "Tag does not match");
    }

    return tagged.item;
  }

  Signed ValueImpl::as_signed() const
  {
    if (!std::holds_alternative<Signed>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a signed value");
    }
    return std::get<Signed>(value);
  }

  Bytes ValueImpl::as_bytes() const
  {
    if (!std::holds_alternative<Bytes>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a bytes value");
    }
    return std::get<Bytes>(value);
  }

  String ValueImpl::as_string() const
  {
    if (!std::holds_alternative<String>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a string value");
    }
    return std::get<String>(value);
  }

  Simple ValueImpl::as_simple() const
  {
    if (!std::holds_alternative<Simple>(value))
    {
      throw CBORDecodeError(Error::TYPE_MISMATCH, "Not a simple value");
    }
    return std::get<Simple>(value);
  }
} // namespace ccf::cbor
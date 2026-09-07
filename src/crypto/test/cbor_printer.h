// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/ds/hex.h"
#include "crypto/test/cbor_printer.h"

#include <cstddef>
#include <sstream>
#include <string>
#include <tav/cbor.hpp>

namespace ccf::cbor::test
{
  inline void print_indent(std::ostringstream& os, size_t indent)
  {
    for (size_t i = 0; i < indent; ++i)
    {
      os << "  ";
    }
  }

  inline std::string format_simple(uint8_t v)
  {
    const auto casted = static_cast<int>(v);
    switch (casted)
    {
      case tav::cbor::SimpleValue::False:
        return "Simple: False";
      case tav::cbor::SimpleValue::True:
        return "Simple: True";
      case tav::cbor::SimpleValue::Null:
        return "Simple: Null";
      case tav::cbor::SimpleValue::Undefined:
        return "Simple: Undefined";
      default:
        return "Simple: " + std::to_string(casted);
    }
  }

  inline void print_value_impl(
    std::ostringstream& os, const tav::cbor::Value& value, size_t indent)
  {
    using tav::cbor::Kind;

    switch (value.kind())
    {
      case Kind::SIGNED:
        print_indent(os, indent);
        os << "Signed: " << value.as_signed() << std::endl;
        break;

      case Kind::BYTES:
      {
        const auto bytes = value.as_bytes();
        print_indent(os, indent);
        os << "Bytes[" << bytes.size() << "]:";
        if (!bytes.empty())
        {
          os << " ";
        }
        os << ccf::ds::to_hex(bytes) << std::endl;
        break;
      }

      case Kind::STRING:
        print_indent(os, indent);
        os << "String: \"" << value.as_string() << "\"" << std::endl;
        break;

      case Kind::ARRAY:
      {
        const auto count = value.size();
        print_indent(os, indent);
        os << "Array[" << count << "]:" << std::endl;
        for (size_t i = 0; i < count; ++i)
        {
          print_value_impl(os, value.array_at(i), indent + 1);
        }
        break;
      }

      case Kind::MAP:
      {
        const auto count = value.size();
        print_indent(os, indent);
        os << "Map[" << count << "]:" << std::endl;
        for (size_t i = 0; i < count; ++i)
        {
          print_indent(os, indent + 1);
          os << "Key:" << std::endl;
          print_value_impl(os, value.map_key_at(i), indent + 2);
          print_indent(os, indent + 1);
          os << "Value:" << std::endl;
          print_value_impl(os, value.map_value_at(i), indent + 2);
        }
        break;
      }

      case Kind::TAGGED:
      {
        const auto tag = value.as_tag();
        print_indent(os, indent);
        os << "Tagged[" << tag << "]:" << std::endl;
        print_value_impl(os, value.tag_at(tag), indent + 1);
        break;
      }

      case Kind::SIMPLE:
        print_indent(os, indent);
        os << format_simple(value.as_simple()) << std::endl;
        break;

      case Kind::INVALID:
      default:
        print_indent(os, indent);
        os << "<null>" << std::endl;
        break;
    }
  }

  inline std::string to_string(const tav::cbor::Value& value)
  {
    std::ostringstream os;
    print_value_impl(os, value, 0);
    auto as_string = os.str();
    if (!as_string.empty() && as_string.back() == '\n')
    {
      as_string.pop_back();
    }
    return as_string;
  }
}

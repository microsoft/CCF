// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "msgpack/encode.h"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf::msgpack::test
{
  inline void encode_json(
    std::vector<uint8_t>& buf, const nlohmann::json& value)
  {
    if (value.is_null())
    {
      write_nil(buf);
    }
    else if (value.is_boolean())
    {
      write_bool(buf, value.get<bool>());
    }
    else if (value.is_number_unsigned())
    {
      write_uint(buf, value.get<uint64_t>());
    }
    else if (value.is_number_integer())
    {
      write_int(buf, value.get<int64_t>());
    }
    else if (value.is_number_float())
    {
      write_float(buf, value.get<double>());
    }
    else if (value.is_string())
    {
      write_str(buf, value.get_ref<const std::string&>());
    }
    else if (value.is_binary())
    {
      const auto& binary = value.get_binary();
      if (binary.has_subtype())
      {
        throw std::logic_error("MessagePack extension values are unsupported");
      }
      write_bin(buf, binary);
    }
    else if (value.is_array())
    {
      write_array_header(buf, static_cast<uint32_t>(value.size()));
      for (const auto& element : value)
      {
        encode_json(buf, element);
      }
    }
    else if (value.is_object())
    {
      write_map_header(buf, static_cast<uint32_t>(value.size()));
      for (const auto& [key, element] : value.items())
      {
        write_str(buf, key);
        encode_json(buf, element);
      }
    }
    else
    {
      throw std::logic_error("Unsupported JSON value");
    }
  }
}

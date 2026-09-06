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
    struct Work
    {
      const nlohmann::json* value = nullptr;
      const std::string* key = nullptr;
    };

    std::vector<Work> pending = {{&value, nullptr}};
    while (!pending.empty())
    {
      const auto work = pending.back();
      pending.pop_back();

      if (work.key != nullptr)
      {
        write_str(buf, *work.key);
        continue;
      }

      const auto& current = *work.value;
      if (current.is_null())
      {
        write_nil(buf);
      }
      else if (current.is_boolean())
      {
        write_bool(buf, current.get<bool>());
      }
      else if (current.is_number_unsigned())
      {
        write_uint(buf, current.get<uint64_t>());
      }
      else if (current.is_number_integer())
      {
        write_int(buf, current.get<int64_t>());
      }
      else if (current.is_number_float())
      {
        write_float(buf, current.get<double>());
      }
      else if (current.is_string())
      {
        write_str(buf, current.get_ref<const std::string&>());
      }
      else if (current.is_binary())
      {
        const auto& binary = current.get_binary();
        if (binary.has_subtype())
        {
          throw std::logic_error(
            "MessagePack extension values are unsupported");
        }
        write_bin(buf, binary);
      }
      else if (current.is_array())
      {
        write_array_header(buf, static_cast<uint32_t>(current.size()));
        const auto& array = current.get_ref<const nlohmann::json::array_t&>();
        for (auto it = array.rbegin(); it != array.rend(); ++it)
        {
          pending.push_back({&*it, nullptr});
        }
      }
      else if (current.is_object())
      {
        write_map_header(buf, static_cast<uint32_t>(current.size()));
        const auto& object = current.get_ref<const nlohmann::json::object_t&>();
        for (auto it = object.rbegin(); it != object.rend(); ++it)
        {
          pending.push_back({&it->second, nullptr});
          pending.push_back({nullptr, &it->first});
        }
      }
      else
      {
        throw std::logic_error("Unsupported JSON value");
      }
    }
  }
}

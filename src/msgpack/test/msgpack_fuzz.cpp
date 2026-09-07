// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "msgpack/test/json.h"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace
{
  using nlohmann::json;

  // Translate every fuzz input into one supported JSON value. Payloads share
  // a fixed budget so nested values cannot cause unbounded allocations.
  class Input
  {
  private:
    const uint8_t* data;
    size_t size;
    size_t offset = 0;
    size_t payload_budget = 65'536;

  public:
    Input(const uint8_t* data_, size_t size_) : data(data_), size(size_) {}

    uint8_t byte()
    {
      return offset < size ? data[offset++] : 0;
    }

    uint64_t uint64()
    {
      uint64_t value = 0;
      for (size_t i = 0; i < sizeof(value); ++i)
      {
        value = (value << 8) | byte();
      }
      return value;
    }

    size_t payload_size()
    {
      // Most selectors produce a small payload. Four sentinel values exercise
      // the str/bin format boundaries without requiring large corpus files.
      const auto selector = byte();
      size_t requested = selector;
      switch (selector)
      {
        case 0:
        case 1:
        case 31:
        case 32:
          break;
        case 252:
          requested = 65'536;
          break;
        case 253:
          requested = 65'535;
          break;
        case 254:
          requested = 256;
          break;
        case 255:
          requested = 255;
          break;
        default:
          requested %= 64;
          break;
      }
      const auto granted = std::min(requested, payload_budget);
      payload_budget -= granted;
      return granted;
    }

    std::string string()
    {
      const auto length = payload_size();
      const auto pattern = byte();
      std::string value(length, '\0');
      for (size_t i = 0; i < length; ++i)
      {
        value[i] = static_cast<char>(32 + ((pattern + i) % 95));
      }
      return value;
    }

    json::binary_t binary()
    {
      const auto length = payload_size();
      const auto pattern = byte();
      json::binary_t value;
      value.resize(length);
      for (size_t i = 0; i < length; ++i)
      {
        value[i] = static_cast<uint8_t>(pattern + i);
      }
      return value;
    }
  };

  json generate_value(Input& input)
  {
    constexpr uint8_t VARIANTS = 9;

    json result;
    std::vector<json*> pending = {&result};

    while (!pending.empty())
    {
      auto* current = pending.back();
      pending.pop_back();

      switch (input.byte() % VARIANTS)
      {
        case 0: // Null
          *current = nullptr;
          break;
        case 1: // Boolean
          *current = (input.byte() & 1) != 0;
          break;
        case 2: // Unsigned integer
          *current = input.uint64();
          break;
        case 3: // Signed integer
        {
          const auto value = std::bit_cast<int64_t>(input.uint64());
          *current =
            value < 0 ? json(value) : json(static_cast<uint64_t>(value));
          break;
        }
        case 4: // Floating-point number
        {
          auto value = std::bit_cast<double>(input.uint64());
          if (!std::isfinite(value))
          {
            value = 0;
          }
          *current = value;
          break;
        }
        case 5: // String
          *current = input.string();
          break;
        case 6: // Binary data
          *current = json::binary(input.binary());
          break;
        case 7: // Array
        {
          *current = json::array();
          auto& array = current->get_ref<json::array_t&>();
          array.resize(input.byte() % 5);
          for (auto it = array.rbegin(); it != array.rend(); ++it)
          {
            pending.push_back(&*it);
          }
          break;
        }
        case 8: // Map
        {
          *current = json::object();
          auto& object = current->get_ref<json::object_t&>();
          const size_t size = input.byte() % 5;
          for (size_t i = 0; i < size; ++i)
          {
            const auto key =
              std::to_string(i) + static_cast<char>('a' + input.byte() % 26);
            object[key] = nullptr;
          }
          for (auto it = object.rbegin(); it != object.rend(); ++it)
          {
            pending.push_back(&it->second);
          }
          break;
        }
        default:
          __builtin_unreachable();
      }
    }

    return result;
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  Input input(data, size);
  const auto expected = generate_value(input);

  std::vector<uint8_t> encoded;
  ccf::msgpack::test::encode_json(encoded, expected);

  if (json::from_msgpack(encoded) != expected)
  {
    __builtin_trap();
  }

  return 0;
}

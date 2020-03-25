// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/json.h"
#include "../ds/serialized.h"
#include "generic_serialise_wrapper.h"
#include "kv_types.h"

#include <iterator>
#include <nlohmann/json.hpp>
#include <sstream>
#include <type_traits>

namespace kv
{
  class JsonWriter;
  template <typename W>
  class GenericSerialiseWrapper;
  using KvStoreSerialiser = GenericSerialiseWrapper<JsonWriter>;

  class JsonReader;
  template <typename W>
  class GenericDeserialiseWrapper;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<JsonReader>;

  class JsonWriter
  {
  private:
    nlohmann::json arr;

  public:
    template <typename T>
    void append(T&& t)
    {
      nlohmann::json obj = t;
      arr.push_back(obj);
    }

    void clear()
    {
      arr.clear();
    }

    bool is_empty()
    {
      return arr.empty();
    }

    std::vector<uint8_t> get_raw_data()
    {
      return nlohmann::json::to_msgpack(arr);
    }
  };

  class JsonReader
  {
  public:
    nlohmann::json arr;
    size_t data_offset;

  public:
    JsonReader(const JsonReader& other) = delete;
    JsonReader& operator=(const JsonReader& other) = delete;

    JsonReader(const uint8_t* data_in_ptr = nullptr, size_t data_in_size = 0)
    {
      init(data_in_ptr, data_in_size);
    }

    void init(const uint8_t* data_in_ptr, size_t data_in_size)
    {
      data_offset = 0;
      if (data_in_ptr && data_in_size)
      {
        arr =
          nlohmann::json::from_msgpack(data_in_ptr, data_in_ptr + data_in_size);
      }
    }

    template <typename T>
    T read_next()
    {
      T ret = peek_next<T>();
      ++data_offset;
      return ret;
    }

    template <typename T>
    T peek_next()
    {
      T ret = arr[data_offset];
      return ret;
    }

    bool is_eos()
    {
      return data_offset >= arr.size();
    }
  };
}

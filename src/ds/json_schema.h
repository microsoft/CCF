// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/nonstd.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace ds
{
  namespace json
  {
    struct JsonSchema
    {
      static constexpr auto hyperschema =
        "http://json-schema.org/draft-07/schema#";

      nlohmann::json schema;
    };

    inline void to_json(nlohmann::json& j, const JsonSchema& s)
    {
      j = s.schema;
    }

    inline void from_json(const nlohmann::json& j, JsonSchema& s)
    {
      s.schema = j;
    }

    template <typename T>
    inline void fill_number_schema(nlohmann::json& schema)
    {
      schema["type"] = "integer";
      schema["minimum"] = std::numeric_limits<T>::min();
      schema["maximum"] = std::numeric_limits<T>::max();
    }

    template <typename T>
    std::string schema_name();

    template <typename T>
    void fill_schema(nlohmann::json& schema);

    template <typename T>
    void fill_json_schema(nlohmann::json& j, const T& t);

    template <typename T>
    nlohmann::json schema_element()
    {
      auto element = nlohmann::json::object();
      fill_schema<T>(element);
      return element;
    }

    template <typename T, typename Doc>
    nlohmann::json schema_element()
    {
      auto element = nlohmann::json::object();
      fill_schema<T>(element);
      return element;
    }

    namespace adl
    {
      template <typename T>
      std::string schema_name()
      {
        T t;
        return schema_name(t);
      }

      template <typename T>
      void fill_schema(nlohmann::json& schema)
      {
        T t;
        if constexpr (std::is_enum<T>::value)
        {
          fill_enum_schema(schema, t);
        }
        else
        {
          fill_json_schema(schema, t);
        }
      }

      template <typename T, typename TDoc>
      nlohmann::json add_schema_to_components(TDoc& doc)
      {
        T t;
        const auto name = schema_name(t);
        const auto ib = doc.components.schemas.try_emplace(name);
        if (ib.second)
        {
          auto& j = ib.first->second;
          add_schema_components(doc, j, t);
        }

        auto schema_ref_object = nlohmann::json::object();
        schema_ref_object["$ref"] =
          fmt::format("#/components/schemas/{}", name);
        return schema_ref_object;
      }
    }

    template <typename T>
    inline std::string schema_name()
    {
      if constexpr (nonstd::is_specialization<T, std::optional>::value)
      {
        return schema_name<typename T::value_type>();
      }
      else if constexpr (nonstd::is_specialization<T, std::vector>::value)
      {
        return fmt::format("{}_array", schema_name<typename T::value_type>());
      }
      else if constexpr (
        nonstd::is_specialization<T, std::map>::value ||
        nonstd::is_specialization<T, std::unordered_map>::value)
      {
        return fmt::format(
          "{}_to_{}",
          schema_name<typename T::key_type>(),
          schema_name<typename T::mapped_type>());
      }
      else if constexpr (nonstd::is_specialization<T, std::pair>::value)
      {
        return fmt::format(
          "{}_to_{}",
          schema_name<typename T::first_type>(),
          schema_name<typename T::second_type>());
      }
      else if constexpr (std::is_same<T, std::string>::value)
      {
        return "string";
      }
      else if constexpr (std::is_same<T, bool>::value)
      {
        return "boolean";
      }
      else if constexpr (std::is_same<T, uint8_t>::value)
      {
        return "uint8";
      }
      else if constexpr (std::is_same<T, uint16_t>::value)
      {
        return "uint16";
      }
      else if constexpr (std::is_same<T, uint32_t>::value)
      {
        return "uint32";
      }
      else if constexpr (std::is_same<T, uint64_t>::value)
      {
        return "uint64";
      }
      else if constexpr (std::is_same<T, int8_t>::value)
      {
        return "int8";
      }
      else if constexpr (std::is_same<T, int16_t>::value)
      {
        return "int16";
      }
      else if constexpr (std::is_same<T, int32_t>::value)
      {
        return "int32";
      }
      else if constexpr (std::is_same<T, int64_t>::value)
      {
        return "int64";
      }
      else if constexpr (std::is_same<T, float>::value)
      {
        return "float";
      }
      else if constexpr (std::is_same<T, double>::value)
      {
        return "double";
      }
      else if constexpr (std::is_same<T, nlohmann::json>::value)
      {
        return "json";
      }
      else
      {
        return adl::schema_name<T>();
      }
    }

    template <typename T>
    inline void fill_schema(nlohmann::json& schema)
    {
      if constexpr (nonstd::is_specialization<T, std::optional>::value)
      {
        fill_schema<typename T::value_type>(schema);
      }
      else if constexpr (nonstd::is_specialization<T, std::vector>::value)
      {
        schema["type"] = "array";
        schema["items"] = schema_element<typename T::value_type>();
      }
      else if constexpr (
        nonstd::is_specialization<T, std::map>::value ||
        nonstd::is_specialization<T, std::unordered_map>::value)
      {
        // Nlohmann serialises maps to an array of (K, V) pairs
        // TODO: Unless the keys are strings!
        schema["type"] = "array";
        auto items = nlohmann::json::object();
        {
          items["type"] = "array";

          auto sub_items = nlohmann::json::array();
          // TODO: OpenAPI doesn't like this tuple for "items", even though its
          // valid JSON schema. Maybe fixed in a newer spec version?
          sub_items.push_back(schema_element<typename T::key_type>());
          sub_items.push_back(schema_element<typename T::mapped_type>());
          items["items"] = sub_items;
        }
        schema["items"] = items;
      }
      else if constexpr (nonstd::is_specialization<T, std::pair>::value)
      {
        schema["type"] = "array";
        auto items = nlohmann::json::array();
        items.push_back(schema_element<typename T::first_type>());
        items.push_back(schema_element<typename T::second_type>());
        schema["items"] = items;
      }
      else if constexpr (std::is_same<T, std::string>::value)
      {
        schema["type"] = "string";
      }
      else if constexpr (std::is_same<T, bool>::value)
      {
        schema["type"] = "boolean";
      }
      else if constexpr (std::is_same<T, nlohmann::json>::value)
      {
        // Any field that contains more json is completely unconstrained, so we
        // do not add a type or any other fields
      }
      else if constexpr (std::is_integral<T>::value)
      {
        fill_number_schema<T>(schema);
      }
      else if constexpr (std::is_floating_point<T>::value)
      {
        schema["type"] = "number";
      }
      else if constexpr (std::is_same<T, JsonSchema>::value)
      {
        schema["$ref"] = JsonSchema::hyperschema;
      }
      else
      {
        adl::fill_schema<T>(schema);
      }
    }

    template <typename T>
    inline nlohmann::json build_schema(const std::string& title)
    {
      nlohmann::json schema;
      schema["$schema"] = JsonSchema::hyperschema;
      schema["title"] = title;

      fill_schema<T>(schema);

      return schema;
    }
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <nlohmann/json.hpp>

namespace ds
{
  namespace json
  {
    namespace
    {
      template <typename T, template <typename...> class U>
      struct is_specialization : std::false_type
      {};

      template <template <typename...> class T, typename... Args>
      struct is_specialization<T<Args...>, T> : std::true_type
      {};

      template <typename T>
      struct dependent_false : public std::false_type
      {};
    };

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
      schema["type"] = "number";
      schema["minimum"] = std::numeric_limits<T>::min();
      schema["maximum"] = std::numeric_limits<T>::max();
    }

    template <typename T>
    void fill_schema(nlohmann::json& schema);

    template <typename T>
    nlohmann::json schema_element()
    {
      auto element = nlohmann::json::object();
      fill_schema<T>(element);
      return element;
    }

    namespace adl
    {
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
    }

    template <typename T>
    inline void fill_schema(nlohmann::json& schema)
    {
      if constexpr (is_specialization<T, std::optional>::value)
      {
        fill_schema<typename T::value_type>(schema);
      }
      else if constexpr (is_specialization<T, std::vector>::value)
      {
        schema["type"] = "array";
        schema["items"] = schema_element<typename T::value_type>();
      }
      else if constexpr (
        is_specialization<T, std::map>::value ||
        is_specialization<T, std::unordered_map>::value)
      {
        // Nlohmann serialises maps to an array of (K, V) pairs
        schema["type"] = "array";
        auto items = nlohmann::json::object();
        {
          items["type"] = "array";

          auto sub_items = nlohmann::json::array();
          sub_items.push_back(schema_element<typename T::key_type>());
          sub_items.push_back(schema_element<typename T::mapped_type>());
          items["items"] = sub_items;
        }
        schema["items"] = items;
      }
      else if constexpr (is_specialization<T, std::pair>::value)
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

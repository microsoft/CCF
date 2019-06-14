// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "json.h"

namespace ccf
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

  template <
    typename T,
    typename = std::enable_if_t<RequiredJsonFields<T>::value>>
  inline void fill_object_schema(nlohmann::json& schema)
  {
    schema["type"] = "object";

    nlohmann::json required = nlohmann::json::array();
    nlohmann::json properties;

    // For all required fields, add the name of the field to required and the
    // schema for the field to properties
    std::apply(
      [&required, &properties](const auto&... field) {
        ((required.push_back(field.name),
          properties[field.name] =
            schema_element<typename std::decay_t<decltype(field)>::Target>()),
         ...);
      },
      RequiredJsonFields<T>::required_fields);

    // Add all optional fields to properties
    if constexpr (OptionalJsonFields<T>::value)
    {
      std::apply(
        [&properties](const auto&... field) {
          ((properties[field.name] =
              schema_element<typename std::decay_t<decltype(field)>::Target>()),
           ...);
        },
        OptionalJsonFields<T>::optional_fields);
    }

    schema["required"] = required;
    schema["properties"] = properties;
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
      // Any field that contains more json is completely unconstrained, so we do
      // not add a type or any other fields
    }
    else if constexpr (std::is_integral<T>::value)
    {
      fill_number_schema<T>(schema);
    }
    else if constexpr (std::is_same<T, JsonSchema>::value)
    {
      schema["$ref"] = JsonSchema::hyperschema;
    }
    else if constexpr (RequiredJsonFields<T>::value)
    {
      fill_object_schema<T>(schema);
    }
    else if constexpr (std::is_enum<T>::value)
    {
      fill_enum_schema<T>(schema);
    }
    else
    {
      static_assert(
        dependent_false<T>::value, "Unsupported type - can't fill schema");
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

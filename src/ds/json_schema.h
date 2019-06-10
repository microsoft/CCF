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
  inline nlohmann::json schema_properties_element_numeric()
  {
    nlohmann::json element;
    element["type"] = "number";
    element["minimum"] = std::numeric_limits<T>::min();
    element["maximum"] = std::numeric_limits<T>::max();

    return element;
  }

  template <typename T>
  nlohmann::json schema_properties_element();

  template <
    typename T,
    typename = std::enable_if_t<RequiredJsonFields<T>::value>>
  inline void fill_schema(nlohmann::json& schema)
  {
    schema["type"] = "object";

    nlohmann::json required = nlohmann::json::array();
    nlohmann::json properties;

    // For all required fields, add the name of the field to required and the
    // schema for the field to properties
    std::apply(
      [&required, &properties](const auto&... field) {
        ((required.push_back(field.name),
          properties[field.name] = schema_properties_element<
            typename std::decay_t<decltype(field)>::Target>()),
         ...);
      },
      RequiredJsonFields<T>::required_fields);

    // Add all optional fields to properties
    if constexpr (OptionalJsonFields<T>::value)
    {
      std::apply(
        [&properties](const auto&... field) {
          ((properties[field.name] = schema_properties_element<
              typename std::decay_t<decltype(field)>::Target>()),
           ...);
        },
        OptionalJsonFields<T>::optional_fields);
    }

    schema["required"] = required;
    schema["properties"] = properties;
  }

  template <typename T>
  inline nlohmann::json schema_properties_element()
  {
    if constexpr (is_specialization<T, std::optional>::value)
    {
      return schema_properties_element<typename T::value_type>();
    }
    else if constexpr (is_specialization<T, std::vector>::value)
    {
      nlohmann::json element;
      element["type"] = "array";
      element["items"] = schema_properties_element<typename T::value_type>();
      return element;
    }
    else if constexpr (std::is_same<T, std::string>::value)
    {
      nlohmann::json element;
      element["type"] = "string";
      return element;
    }
    else if constexpr (std::is_same<T, bool>::value)
    {
      nlohmann::json element;
      element["type"] = "boolean";
      return element;
    }
    else if constexpr (std::is_same<T, nlohmann::json>::value)
    {
      // Any field that contains more json is completely unconstrained
      return nlohmann::json::object();
    }
    else if constexpr (std::is_integral<T>::value)
    {
      return schema_properties_element_numeric<T>();
    }
    else if constexpr (std::is_same<T, JsonSchema>::value)
    {
      nlohmann::json element;
      element["$ref"] = JsonSchema::hyperschema;
      return element;
    }
    else if constexpr (RequiredJsonFields<T>::value)
    {
      auto schema = nlohmann::json::object();
      fill_schema<T>(schema);
      return schema;
    }
    else
    {
      static_assert(
        dependent_false<T>::value,
        "Unsupported type - can't create schema element");
      return nullptr;
    }
  }

  template <
    typename T,
    typename = std::enable_if_t<RequiredJsonFields<T>::value>>
  inline nlohmann::json build_schema(const std::string& title)
  {
    nlohmann::json schema;
    schema["$schema"] = JsonSchema::hyperschema;
    schema["title"] = title;

    fill_schema<T>(schema);

    return schema;
  }
}

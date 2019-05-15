// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "json.h"

namespace ccf
{
  template <typename T>
  nlohmann::json schema_properties_element();

  template <>
  inline nlohmann::json schema_properties_element<nlohmann::json>()
  {
    // Any field that contains more json is completely unconstrained
    return nlohmann::json::object();
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

  template <>
  inline nlohmann::json schema_properties_element<size_t>()
  {
    return schema_properties_element_numeric<size_t>();
  }

  template <>
  inline nlohmann::json schema_properties_element<int>()
  {
    return schema_properties_element_numeric<int>();
  }

  template <>
  inline nlohmann::json schema_properties_element<long>()
  {
    return schema_properties_element_numeric<long>();
  }

  template <>
  inline nlohmann::json schema_properties_element<std::string>()
  {
    nlohmann::json element;
    element["type"] = "string";
    return element;
  }

  template <
    typename T,
    typename = std::enable_if_t<RequiredJsonFields<T>::value>>
  inline nlohmann::json build_schema(const std::string& title)
  {
    nlohmann::json schema;
    schema["$id"] =
      "http://https://github.com/Microsoft/CCF/schemas/" + title + ".json";
    schema["$schema"] = "http://json-schema.org/draft-07/schema#";
    schema["title"] = title;
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

    return schema;
  }
}

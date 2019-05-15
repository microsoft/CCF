// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "json.h"

namespace ccf
{
  template <typename T>
  nlohmann::json schema_properties_element()
  {
    // Without a tighter specialization, elements are unconstrained
    return {};
  }

  template <>
  inline nlohmann::json schema_properties_element<JsonField<size_t>>()
  {
    nlohmann::json element;
    element["type"] = "number";
    return element;
  }

  template <>
  inline nlohmann::json schema_properties_element<JsonField<std::string>>()
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
    schema["$id"] = "http://https://github.com/Microsoft/CCF/schemas/" + title +
      ".schema.json";
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
          properties[field.name] =
            schema_properties_element<std::decay_t<decltype(field)>>()),
         ...);
      },
      RequiredJsonFields<T>::required_fields);

    // Add all optional fields to properties
    if constexpr (OptionalJsonFields<T>::value)
    {
      std::apply(
        [&properties](const auto&... field) {
          ((properties[field.name] =
              schema_properties_element<std::decay_t<decltype(field)>>()),
           ...);
        },
        OptionalJsonFields<T>::optional_fields);
    }

    schema["required"] = required;
    schema["properties"] = properties;

    return schema;
  }
}

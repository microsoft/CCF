// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "ds/nonstd.h"

#include <http-parser/http_parser.h>
#include <nlohmann/json.hpp>
#include <string>

namespace ds
{
  /**
   * These structs contain the required fields to build the corresponding
   * OpenAPI objects. They do not contain every field, but should be trivially
   * extensible with any which are desired.
   */
  namespace openapi
  {
    struct Info
    {
      std::string title;
      std::string description;
      std::string version;
    };
    DECLARE_JSON_TYPE(Info);
    DECLARE_JSON_REQUIRED_FIELDS(Info, title, description, version);

    struct Server
    {
      std::string url;

      bool operator==(const Server& rhs) const
      {
        return url == rhs.url;
      }
    };
    DECLARE_JSON_TYPE(Server);
    DECLARE_JSON_REQUIRED_FIELDS(Server, url);

    struct MediaType
    {
      // May be a full in-place schema, but is generally a reference object
      nlohmann::json schema;

      bool operator==(const MediaType& rhs) const
      {
        return schema == rhs.schema;
      }
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(MediaType);
    DECLARE_JSON_REQUIRED_FIELDS(MediaType);
    DECLARE_JSON_OPTIONAL_FIELDS(MediaType, schema);

    using ContentMap = std::map<std::string, MediaType>;

    struct RequestBody
    {
      std::string description;
      ContentMap content;
      bool required = false;

      bool operator==(const RequestBody& rhs) const
      {
        return description == rhs.description && content == rhs.content &&
          required == rhs.required;
      }

      bool operator!=(const RequestBody& rhs) const
      {
        return !(*this == rhs);
      }
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(RequestBody);
    DECLARE_JSON_REQUIRED_FIELDS(RequestBody, content);
    DECLARE_JSON_OPTIONAL_FIELDS(RequestBody, description, required);

    struct Response
    {
      std::string description;
      ContentMap content;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Response);
    DECLARE_JSON_REQUIRED_FIELDS(Response, description);
    DECLARE_JSON_OPTIONAL_FIELDS(Response, content);

    struct Operation
    {
      RequestBody requestBody;
      std::map<std::string, Response> responses;

      Response& operator[](http_status status)
      {
        // HTTP_STATUS_OK (aka an int with value 200) becomes the string "200"
        const auto s = std::to_string(status);
        return responses[s];
      }
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Operation);
    DECLARE_JSON_REQUIRED_FIELDS(Operation, responses);
    DECLARE_JSON_OPTIONAL_FIELDS(Operation, requestBody);

    struct PathItem
    {
      std::map<std::string, Operation> operations;

      Operation& operator[](http_method verb)
      {
        // HTTP_GET becomes the string "get"
        std::string s = http_method_str(verb);
        nonstd::to_lower(s);
        return operations[s];
      }
    };

    // When converted to JSON, a PathItem is not an object containing an
    // 'operations' field with an object value, it _is_ this operations object
    // value
    inline void to_json(nlohmann::json& j, const PathItem& pi)
    {
      j = pi.operations;
    }

    inline void from_json(const nlohmann::json& j, PathItem& pi)
    {
      pi.operations = j.get<decltype(pi.operations)>();
    }

    using Paths = std::map<std::string, PathItem>;

    inline void check_path_valid(const std::string& s)
    {
      if (s.rfind("/", 0) != 0)
      {
        throw std::logic_error(
          fmt::format("'{}' is not a valid path - must begin with '/'", s));
      }
    }

    struct Components
    {
      std::map<std::string, nlohmann::json> schemas;

      bool operator!=(const Components& rhs) const
      {
        return schemas != rhs.schemas;
      }
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Components);
    DECLARE_JSON_REQUIRED_FIELDS(Components);
    DECLARE_JSON_OPTIONAL_FIELDS(Components, schemas);

    struct Document
    {
      std::string openapi = "3.0.0";
      Info info;
      std::vector<Server> servers;
      Paths paths;
      Components components;

      nlohmann::json add_schema_to_components(
        const std::string& element_name, const nlohmann::json& schema)
      {
        const auto schema_it = components.schemas.find(element_name);
        if (schema_it != components.schemas.end())
        {
          // Check that the existing schema matches the new one being added with
          // the same name
          const auto& existing_schema = schema_it->second;
          if (schema != existing_schema)
          {
            throw std::logic_error(fmt::format(
              "Adding schema with name '{}'. Does not match previous schema "
              "registered with this name: {} vs {}",
              element_name,
              schema.dump(),
              existing_schema.dump()));
          }
        }
        else
        {
          components.schemas.emplace(element_name, schema);
        }

        auto schema_ref_object = nlohmann::json::object();
        schema_ref_object["$ref"] =
          fmt::format("#/components/schemas/{}", element_name);
        return schema_ref_object;
      }

      void add_request_body_schema(
        const std::string& uri,
        http_method verb,
        const std::string& content_type,
        const std::string& schema_name,
        const nlohmann::json& schema)
      {
        check_path_valid(uri);

        auto& request_body = paths[uri][verb].requestBody;
        request_body.description = "Auto-generated request body schema";
        request_body.content[content_type].schema =
          add_schema_to_components(schema_name, schema);
      }

      template <typename T>
      void add_request_body_schema(
        const std::string& uri,
        http_method verb,
        const std::string& content_type)
      {
        check_path_valid(uri);

        auto& request_body = paths[uri][verb].requestBody;
        request_body.description = "Auto-generated request body schema";
        request_body.content[content_type].schema =
          add_schema_component<T>();
      }

      void add_response_schema(
        const std::string& uri,
        http_method verb,
        http_status status,
        const std::string& content_type,
        const std::string& schema_name,
        const nlohmann::json& schema)
      {
        check_path_valid(uri);

        auto& response_object = paths[uri][verb][status];
        response_object.description = "Auto-generated response schema";
        response_object.content[content_type].schema =
          add_schema_to_components(schema_name, schema);
      }

      template <typename T>
      void add_response_schema(
        const std::string& uri,
        http_method verb,
        http_status status,
        const std::string& content_type)
      {
        check_path_valid(uri);

        auto& response_object = paths[uri][verb][status];
        response_object.description = "Auto-generated response schema";
        response_object.content[content_type].schema =
          add_schema_component<T>();
      }

      template <typename T>
      inline nlohmann::json add_schema_component()
      {
        nlohmann::json j;
        // if constexpr (nonstd::is_specialization<T, std::optional>::value)
        // {
        //   return schema_name<typename T::value_type>();
        // }
        // else if constexpr (nonstd::is_specialization<T, std::vector>::value)
        // {
        //   return fmt::format("{}_array", schema_name<typename
        //   T::value_type>());
        // }
        // else if constexpr (
        //   nonstd::is_specialization<T, std::map>::value ||
        //   nonstd::is_specialization<T, std::unordered_map>::value)
        // {
        //   return fmt::format(
        //     "{}_to_{}",
        //     schema_name<typename T::key_type>(),
        //     schema_name<typename T::mapped_type>());
        // }
        // else if constexpr (nonstd::is_specialization<T, std::pair>::value)
        // {
        //   return fmt::format(
        //     "{}_to_{}",
        //     schema_name<typename T::first_type>(),
        //     schema_name<typename T::second_type>());
        // }
        // else
        if constexpr (
          std::is_same<T, std::string>::value || std::is_same<T, bool>::value ||
          std::is_same<T, uint8_t>::value || std::is_same<T, uint16_t>::value ||
          std::is_same<T, uint32_t>::value ||
          std::is_same<T, uint64_t>::value || std::is_same<T, int8_t>::value ||
          std::is_same<T, int16_t>::value || std::is_same<T, int32_t>::value ||
          std::is_same<T, int64_t>::value || std::is_same<T, float>::value ||
          std::is_same<T, double>::value ||
          std::is_same<T, nlohmann::json>::value)
        {
          ds::json::fill_schema<T>(j);
          return add_schema_to_components(ds::json::schema_name<T>(), j);
        }
        else
        {
          return ds::json::adl::add_schema_to_components<T>(*this);
        }
      }
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Document);
    DECLARE_JSON_REQUIRED_FIELDS(Document, openapi, info, paths);
    DECLARE_JSON_OPTIONAL_FIELDS(Document, servers, components);
  }
}

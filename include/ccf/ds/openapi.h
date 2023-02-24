// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/ds/nonstd.h"
#include "ccf/http_consts.h"
#include "ccf/http_status.h"

#include <llhttp/llhttp.h>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>
#include <string_view>

namespace ds
{
  /**
   * This namespace contains helper functions, structs, and templates for
   * modifying an OpenAPI JSON document. They do not set every field, but should
   * fill every _required_ field, and the resulting object can be further
   * modified by hand as required.
   */
  namespace openapi
  {
    namespace access
    {
      static inline nlohmann::json& get_object(
        nlohmann::json& j, const std::string_view& k)
      {
        const auto ib = j.emplace(k, nlohmann::json::object());
        return ib.first.value();
      }

      static inline nlohmann::json& get_array(
        nlohmann::json& j, const std::string_view& k)
      {
        const auto ib = j.emplace(k, nlohmann::json::array());
        return ib.first.value();
      }
    }

    static inline std::string sanitise_components_key(const std::string_view& s)
    {
      // From the OpenAPI spec:
      // All the fixed fields declared above are objects that MUST use keys that
      // match the regular expression: ^[a-zA-Z0-9\.\-_]+$
      // So here we replace any non-matching characters with _
      std::string result;
      std::regex re("[^a-zA-Z0-9\\.\\-_]");
      std::regex_replace(
        std::back_inserter(result), s.begin(), s.end(), re, "_");
      return result;
    }

    static inline nlohmann::json create_document(
      const std::string_view& title,
      const std::string_view& description,
      const std::string_view& document_version)
    {
      return nlohmann::json{
        {"openapi", "3.0.0"},
        {"info",
         {{"title", title},
          {"description", description},
          {"version", document_version}}},
        {"servers", nlohmann::json::array()},
        {"paths", nlohmann::json::object()}};
    }

    static inline nlohmann::json& server(
      nlohmann::json& document, const std::string_view& url)
    {
      auto& servers = access::get_object(document, "servers");
      servers.push_back({{"url", url}});
      return servers.back();
    }

    static inline nlohmann::json& path(
      nlohmann::json& document, const std::string_view& path)
    {
      auto p = path;
      if (p.find("/") != 0)
      {
        p = fmt::format("/{}", p);
      }

      auto& paths = access::get_object(document, "paths");
      return access::get_object(paths, p);
    }

    static inline nlohmann::json& path_operation(
      nlohmann::json& path, llhttp_method verb, bool default_responses = true)
    {
      // HTTP_GET becomes the string "get"
      std::string s = llhttp_method_name(verb);
      nonstd::to_lower(s);
      auto& po = access::get_object(path, s);

      if (default_responses)
      {
        // responses is required field in a path_operation, but caller may
        // choose to add their own later
        access::get_object(po, "responses");
      }

      return po;
    }

    static inline nlohmann::json& parameters(nlohmann::json& path_operation)
    {
      return access::get_array(path_operation, "parameters");
    }

    static inline nlohmann::json& responses(nlohmann::json& path_operation)
    {
      return access::get_object(path_operation, "responses");
    }

    static inline nlohmann::json& response(
      nlohmann::json& path_operation,
      http_status status,
      const std::string_view& description = "Default response description")
    {
      auto& all_responses = responses(path_operation);

      // HTTP_STATUS_OK (aka an int-enum with value 200) becomes the string
      // "200"
      const auto s = std::to_string(status);
      auto& response = access::get_object(all_responses, s);
      response["description"] = description;
      return response;
    }

    static inline nlohmann::json& error_response_default(
      nlohmann::json& path_operation)
    {
      auto& all_responses = responses(path_operation);
      auto& response = access::get_object(all_responses, "default");
      response["$ref"] = "#/components/responses/default";
      return response;
    }

    static inline nlohmann::json& request_body(nlohmann::json& path_operation)
    {
      auto& request_body = access::get_object(path_operation, "requestBody");
      access::get_object(request_body, "content");
      return request_body;
    }

    static inline nlohmann::json& media_type(
      nlohmann::json& j, const std::string_view& mt)
    {
      auto& content = access::get_object(j, "content");
      return access::get_object(content, mt);
    }

    static inline nlohmann::json& schema(nlohmann::json& media_type_object)
    {
      return access::get_object(media_type_object, "schema");
    }

    static inline nlohmann::json& extension(
      nlohmann::json& object, const std::string_view& extension_name)
    {
      if (!extension_name.starts_with("x-"))
      {
        throw std::logic_error(fmt::format(
          "Adding extension with name '{}'. Extension fields must begin with "
          "'x-'",
          extension_name));
      }

      return access::get_object(object, extension_name);
    }

    //
    // Helper functions for auto-inserting schema into components
    //

    static inline nlohmann::json components_ref_object(
      const std::string_view& element_name)
    {
      auto schema_ref_object = nlohmann::json::object();
      schema_ref_object["$ref"] =
        fmt::format("#/components/schemas/{}", element_name);
      return schema_ref_object;
    }

    // Returns a ref object pointing to the item inserted into the components
    static inline nlohmann::json add_schema_to_components(
      nlohmann::json& document,
      const std::string_view& element_name,
      const nlohmann::json& schema_)
    {
      const auto name = sanitise_components_key(element_name);

      auto& components = access::get_object(document, "components");
      auto& schemas = access::get_object(components, "schemas");

      const auto schema_it = schemas.find(name);
      if (schema_it != schemas.end())
      {
        // Check that the existing schema matches the new one being added with
        // the same name
        const auto& existing_schema = schema_it.value();
        if (schema_ != existing_schema)
        {
          throw std::logic_error(fmt::format(
            "Adding schema with name '{}'. Does not match previous schema "
            "registered with this name: {} vs {}",
            name,
            schema_.dump(),
            existing_schema.dump()));
        }
      }
      else
      {
        schemas.emplace(name, schema_);
      }

      return components_ref_object(name);
    }

    static inline void add_security_scheme_to_components(
      nlohmann::json& document,
      const std::string_view& scheme_name,
      const nlohmann::json& security_scheme)
    {
      const auto name = sanitise_components_key(scheme_name);

      auto& components = access::get_object(document, "components");
      auto& schemes = access::get_object(components, "securitySchemes");

      const auto schema_it = schemes.find(name);
      if (schema_it != schemes.end())
      {
        // Check that the existing schema matches the new one being added with
        // the same name
        const auto& existing_scheme = schema_it.value();
        if (security_scheme != existing_scheme)
        {
          throw std::logic_error(fmt::format(
            "Adding security scheme with name '{}'. Does not match previous "
            "scheme registered with this name: {} vs {}",
            name,
            security_scheme.dump(),
            existing_scheme.dump()));
        }
      }
      else
      {
        schemes.emplace(name, security_scheme);
      }
    }

    // This adds a schema description of T to the object j, potentially
    // modifying another part of the given Doc (for instance, by adding the
    // schema to a shared component in the document, and making j be a reference
    // to that). This default implementation simply falls back to
    // fill_json_schema, which already exists to describe leaf types. A
    // recursive implementation for struct-to-object types is created by the
    // json.h macros, and this could be implemented manually for other types.
    template <typename Doc, typename T>
    void add_schema_components(Doc&, nlohmann::json& j, const T* t)
    {
      fill_json_schema(j, t);
    }

    struct SchemaHelper
    {
      nlohmann::json& document;

      template <typename T>
      nlohmann::json add_schema_component()
      {
        nlohmann::json schema;
        if constexpr (nonstd::is_specialization<T, std::optional>::value)
        {
          return add_schema_component<typename T::value_type>();
        }
        else if constexpr (
          nonstd::is_specialization<T, std::vector>::value ||
          nonstd::is_specialization<T, std::set>::value)
        {
          if constexpr (std::is_same<T, std::vector<uint8_t>>::value)
          {
            // Byte vectors are always base64 encoded
            schema["type"] = "string";
            schema["format"] = "base64";
          }
          else
          {
            schema["type"] = "array";
            schema["items"] = add_schema_component<typename T::value_type>();
          }

          return add_schema_to_components(
            document, ds::json::schema_name<T>(), schema);
        }
        else if constexpr (
          nonstd::is_specialization<T, std::map>::value ||
          nonstd::is_specialization<T, std::unordered_map>::value)
        {
          if constexpr (nlohmann::detail::
                          is_compatible_object_type<nlohmann::json, T>::value)
          {
            schema["type"] = "object";
            schema["additionalProperties"] =
              add_schema_component<typename T::mapped_type>();
          }
          else
          {
            schema["type"] = "array";
            auto items = nlohmann::json::object();
            {
              items["type"] = "array";

              auto sub_items = nlohmann::json::array();
              sub_items.push_back(add_schema_component<typename T::key_type>());
              sub_items.push_back(
                add_schema_component<typename T::mapped_type>());

              items["items"]["oneOf"] = sub_items;
              items["minItems"] = 2;
              items["maxItems"] = 2;
            }
            schema["items"] = items;
          }
          return add_schema_to_components(
            document, ds::json::schema_name<T>(), schema);
        }
        else if constexpr (nonstd::is_specialization<T, std::pair>::value)
        {
          schema["type"] = "array";
          auto items = nlohmann::json::array();
          items.push_back(add_schema_component<typename T::first_type>());
          items.push_back(add_schema_component<typename T::second_type>());
          schema["items"] = items;
          return add_schema_to_components(
            document, ds::json::schema_name<T>(), schema);
        }
        else if constexpr (
          std::is_same<T, std::string>::value || std::is_arithmetic_v<T> ||
          std::is_same<T, nlohmann::json>::value ||
          std::is_same<T, ds::json::JsonSchema>::value)
        {
          ds::json::fill_schema<T>(schema);
          return add_schema_to_components(
            document, ds::json::schema_name<T>(), schema);
        }
        else
        {
          const auto name = sanitise_components_key(ds::json::schema_name<T>());

          auto& components = access::get_object(document, "components");
          auto& schemas = access::get_object(components, "schemas");

          const auto ib = schemas.emplace(name, nlohmann::json::object());
          if (ib.second)
          {
            auto& j = ib.first.value();

#pragma clang diagnostic push
#if defined(__clang__) && __clang_major__ >= 11
#  pragma clang diagnostic ignored "-Wuninitialized-const-reference"
#endif
            // Use argument-dependent-lookup to call correct functions
            T* t = nullptr;
            if constexpr (std::is_enum<T>::value)
            {
              fill_enum_schema(j, t);
            }
            else
            {
              add_schema_components(*this, j, t);
            }
#pragma clang diagnostic pop
          }

          return components_ref_object(name);
        }
      }
    };

    template <typename T>
    static inline char const* auto_content_type()
    {
      if constexpr (std::is_same_v<T, std::string>)
      {
        return http::headervalues::contenttype::TEXT;
      }
      else
      {
        return http::headervalues::contenttype::JSON;
      }
    }

    static inline void add_request_body_schema(
      nlohmann::json& document,
      const std::string_view& uri,
      llhttp_method verb,
      const std::string_view& content_type,
      const std::string_view& schema_name,
      const nlohmann::json& schema_)
    {
      auto& rb = request_body(path_operation(path(document, uri), verb));
      rb["description"] = "Auto-generated request body schema";

      schema(media_type(rb, content_type)) =
        add_schema_to_components(document, schema_name, schema_);
    }

    template <typename T>
    static inline void add_request_body_schema(
      nlohmann::json& document, const std::string_view& uri, llhttp_method verb)
    {
      auto& rb = request_body(path_operation(path(document, uri), verb));
      rb["description"] = "Auto-generated request body schema";

      SchemaHelper sh{document};
      const auto schema_comp = sh.add_schema_component<T>();
      if (schema_comp != nullptr)
      {
        schema(media_type(rb, auto_content_type<T>())) =
          sh.add_schema_component<T>();
      }
    }

    static inline void add_path_parameter_schema(
      nlohmann::json& document,
      const std::string_view& uri,
      const nlohmann::json& param)
    {
      auto& params = parameters(path(document, uri));
      for (auto& p : params)
      {
        if (p["name"] == param["name"])
          return;
      }
      params.push_back(param);
    }

    static inline void add_request_parameter_schema(
      nlohmann::json& document,
      const std::string_view& uri,
      llhttp_method verb,
      const nlohmann::json& param)
    {
      auto& params = parameters(path_operation(path(document, uri), verb));
      params.push_back(param);
    }

    static inline void add_response_schema(
      nlohmann::json& document,
      const std::string_view& uri,
      llhttp_method verb,
      http_status status,
      const std::string_view& content_type,
      const std::string_view& schema_name,
      const nlohmann::json& schema_)
    {
      auto& r = response(path_operation(path(document, uri), verb), status);

      schema(media_type(r, content_type)) =
        add_schema_to_components(document, schema_name, schema_);
    }

    template <typename T>
    static inline void add_response_schema(
      nlohmann::json& document,
      const std::string_view& uri,
      llhttp_method verb,
      http_status status)
    {
      auto& r = response(path_operation(path(document, uri), verb), status);

      SchemaHelper sh{document};
      const auto schema_comp = sh.add_schema_component<T>();
      if (schema_comp != nullptr)
      {
        schema(media_type(r, auto_content_type<T>())) =
          sh.add_schema_component<T>();
      }
    }
  }
}

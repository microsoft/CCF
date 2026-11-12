// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json_schema.h"
#include "ccf/json/serialization.h"

#include <algorithm>
#include <glaze/json/schema.hpp>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>

namespace ccf::json::detail
{
  inline constexpr auto schema_opts = [] {
    struct SchemaOptions : ccf::json::Options
    {
      bool write_type_info = false;
    };
    auto options = SchemaOptions{ccf::json::options};
    // These are optional members of glz::schema, not of the described type.
    options.skip_null_members = true;
    return options;
  }();

  inline std::string component_name(std::string_view name)
  {
    std::string result(name);
    for (auto& c : result)
    {
      const bool valid = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
      if (!valid)
      {
        c = '_';
      }
    }
    return result;
  }

  // Only recurse into schema-valued keywords, never examples/default/const
  // data.
  template <typename Transform>
  Json transform_schema(Json schema, const Transform& transform)
  {
    if (schema.is_boolean())
    {
      return schema;
    }
    if (!schema.is_object())
    {
      throw std::logic_error("Expected a JSON Schema object or boolean");
    }
    for (const auto* key :
         {"$defs", "properties", "patternProperties", "dependentSchemas"})
    {
      if (schema.contains(key))
      {
        for (const auto& [name, child] : schema[key].items())
        {
          child = transform_schema(std::move(child), transform);
        }
      }
    }
    for (const auto* key :
         {"items",
          "additionalProperties",
          "contains",
          "propertyNames",
          "unevaluatedItems",
          "unevaluatedProperties",
          "not",
          "if",
          "then",
          "else",
          "contentSchema"})
    {
      if (schema.contains(key))
      {
        schema[key] = transform_schema(std::move(schema[key]), transform);
      }
    }
    for (const auto* key : {"prefixItems", "allOf", "anyOf", "oneOf"})
    {
      if (schema.contains(key))
      {
        for (auto& child : schema[key])
        {
          child = transform_schema(std::move(child), transform);
        }
      }
    }
    return transform(std::move(schema));
  }

  inline Json prepare_schema(Json schema)
  {
    auto adl_definitions = Json::object();
    if (schema.is_object() && schema.contains("$defs"))
    {
      auto& definitions = schema["$defs"];
      for (auto it = definitions.begin(); it != definitions.end();)
      {
        if (
          it.key().starts_with("ccf.adl.") ||
          it.key().starts_with("ccf.openapi."))
        {
          adl_definitions[it.key()] = std::move(it.value());
          it = definitions.erase(it);
        }
        else
        {
          ++it;
        }
      }
    }
    auto result = transform_schema(std::move(schema), [](Json node) {
      if (node.contains("oneOf") && !node["oneOf"].empty())
      {
        auto values = Json::array();
        bool plain_enum = true;
        for (const auto& branch : node["oneOf"])
        {
          if (
            !branch.is_object() || !branch.contains("const") ||
            branch.size() != (branch.contains("title") ? 2 : 1) ||
            (branch.contains("title") && branch["title"] != branch["const"]) ||
            std::find(values.begin(), values.end(), branch["const"]) !=
              values.end())
          {
            plain_enum = false;
            break;
          }
          values.push_back(branch["const"]);
        }
        if (plain_enum)
        {
          node.erase("oneOf");
          node["enum"] = std::move(values);
        }
      }
      if (
        node.value("type", Json()) == "object" &&
        node.contains("additionalProperties") &&
        node["additionalProperties"].is_boolean())
      {
        // Generated record schemas need no explicit permissive default.
        node.erase("additionalProperties");
      }
      if (
        node.contains("prefixItems") && node.value("items", Json()) == false &&
        node.value("maxItems", Json()) == node["prefixItems"].size() &&
        !node.contains("minItems"))
      {
        // Glaze 9 emits the upper tuple bound but omits the lower bound.
        node["minItems"] = node["prefixItems"].size();
      }
      if (
        node.contains("oneOf") &&
        std::any_of(
          node["oneOf"].begin(), node["oneOf"].end(), [](const Json& branch) {
            return !branch.contains("const");
          }))
      {
        // Generated variant alternatives may overlap (objects or int/double).
        // Keep their constraints, but accept membership in any alternative.
        auto alternatives = std::move(node["oneOf"]);
        node.erase("oneOf");
        if (node.contains("anyOf"))
        {
          if (!node.contains("allOf"))
          {
            node["allOf"] = Json::array();
          }
          node["allOf"].push_back(Json{{"anyOf", std::move(alternatives)}});
        }
        else
        {
          node["anyOf"] = std::move(alternatives);
        }
      }
      return node;
    });
    for (const auto& [name, definition] : adl_definitions.items())
    {
      result["$defs"][name] = std::move(definition);
    }
    return result;
  }

  inline Json rebase_schema(
    const Json& schema,
    const std::string& base,
    bool keep_component_references = false)
  {
    return transform_schema(schema, [&](Json node) {
      if (node.contains("$ref"))
      {
        const auto reference = node.at("$ref").get<std::string>();
        if (
          keep_component_references &&
          reference.starts_with("#/components/schemas/"))
        {
          return node;
        }
        if (reference.starts_with('#'))
        {
          // Fail on dangling local references before publishing a document.
          (void)schema.at(Json::json_pointer(reference.substr(1)));
          node["$ref"] = base + reference.substr(1);
        }
      }
      return node;
    });
  }

  inline Json inline_references(
    Json source, const Json& root, std::set<std::string>& expanding)
  {
    if (source.is_boolean())
    {
      return source;
    }
    source.erase("$defs");
    source.erase("$schema");
    return transform_schema(std::move(source), [&](Json node) {
      if (!node.contains("$ref"))
      {
        return node;
      }
      const auto reference = node.at("$ref").get<std::string>();
      if (!reference.starts_with('#'))
      {
        throw std::logic_error(
          "External references cannot be expanded in a standalone schema");
      }
      if (!expanding.insert(reference).second)
      {
        throw std::logic_error("Recursive schemas require a component schema");
      }
      auto target = inline_references(
        root.at(Json::json_pointer(reference.substr(1))), root, expanding);
      expanding.erase(reference);
      node.erase("$ref");
      return node.empty() ? target :
                            Json{{"allOf", Json::array({target, node})}};
    });
  }

  struct SchemaDocument
  {
    Json document = Json{{"components", {{"schemas", Json::object()}}}};

    template <typename T>
    Json add_schema_component();

    template <typename T>
    Json add_required_schema_component();
  };

  template <typename T>
  concept AdlSchemaFill =
    requires(Json& schema, const T* tag) { fill_json_schema(schema, tag); };

  template <typename T>
  concept AdlSchemaComponents =
    requires(SchemaDocument& document, Json& schema, const T* tag) {
      add_schema_components(document, schema, tag);
    };

  // Glaze's schema model cannot represent arbitrary custom keywords or formats.
  // Collect exact ADL schemas separately rather than dropping those
  // constraints. A scoped, thread-local context supports concurrent and nested
  // generation.
  struct SchemaContext
  {
    inline static thread_local SchemaContext* current = nullptr;
    SchemaContext* previous = current;
    Json definitions = Json::object();
    SchemaDocument* document = nullptr;

    SchemaContext()
    {
      current = this;
    }

    ~SchemaContext()
    {
      current = previous;
    }

    SchemaContext(const SchemaContext&) = delete;
    SchemaContext& operator=(const SchemaContext&) = delete;
  };

  inline std::string escape_pointer(std::string_view value)
  {
    std::string result;
    for (const auto c : value)
    {
      if (c == '~')
      {
        result += "~0";
      }
      else if (c == '/')
      {
        result += "~1";
      }
      else
      {
        result += c;
      }
    }
    return result;
  }

  template <DomAdapter T>
  const std::string& adl_schema_reference()
  {
    static const std::string name =
      "ccf.adl." + ccf::ds::json::schema_name<T>();
    static const std::string reference = "#/$defs/" + escape_pointer(name);
    auto* context = SchemaContext::current;
    if (context == nullptr)
    {
      throw std::logic_error("CCF ADL schemas require ccf::json::schema<T>()");
    }
    if (!context->definitions.contains(name))
    {
      auto schema = Json::object();
      if constexpr (AdlLeaf<T>)
      {
        if constexpr (AdlSchemaComponents<T>)
        {
          schema = context->document->template add_schema_component<T>();
        }
        else if constexpr (AdlSchemaFill<T>)
        {
          fill_json_schema(schema, static_cast<const T*>(nullptr));
        }
        else
        {
          static_assert(
            AdlSchemaComponents<T>,
            "Custom JSON types require ADL fill_json_schema or "
            "add_schema_components");
        }
      }
      else
      {
        ccf::ds::json::fill_schema<T>(schema);
      }
      try
      {
        context->definitions[name] = rebase_schema(schema, reference, true);
      }
      catch (const std::logic_error& error)
      {
        throw std::logic_error(
          "Invalid ADL schema for " + name + ": " + error.what());
      }
    }
    return reference;
  }

  template <DomAdapter T>
  struct AdlSchema
  {
    template <auto Options>
    static void op(auto& schema, [[maybe_unused]] auto& definitions)
    {
      schema.ref = adl_schema_reference<T>();
    }
  };

  template <typename T, auto Options = schema_opts>
  Json native_schema(SchemaDocument* shared_document = nullptr)
  {
    SchemaContext context;
    SchemaDocument document;
    context.document = shared_document != nullptr ? shared_document : &document;
    // Keep definitions until CCF can share them across the entire document.
    glz::schema native{};
    native.defs.emplace();
    glz::detail::to_json_schema<T>::template op<Options>(native, *native.defs);
    const auto result = glz::write<Options>(native);
    if (!result)
    {
      throw std::logic_error(glz::format_error(result.error(), ""));
    }
    auto schema = Json::parse(*result);
    for (const auto& [name, definition] : context.definitions.items())
    {
      schema["$defs"][name] = std::move(definition);
    }
    if (shared_document == nullptr)
    {
      for (const auto& [name, definition] :
           document.document["components"]["schemas"].items())
      {
        schema["$defs"]["ccf.openapi." + name] = definition;
      }
      schema = transform_schema(std::move(schema), [](Json node) {
        if (node.contains("$ref"))
        {
          const auto reference = node.at("$ref").get<std::string>();
          constexpr std::string_view prefix = "#/components/schemas/";
          if (reference.starts_with(prefix))
          {
            node["$ref"] =
              "#/$defs/ccf.openapi." + reference.substr(prefix.size());
          }
        }
        return node;
      });
    }
    return schema;
  }

  template <typename T>
  Json standalone_schema()
  {
    try
    {
      const auto schema = prepare_schema(native_schema<T>());
      std::set<std::string> expanding;
      return inline_references(schema, schema, expanding);
    }
    catch (const Json::out_of_range& error)
    {
      throw std::logic_error(
        "Invalid standalone schema for '" + std::string(glz::name_v<T>) +
        "': " + error.what());
    }
  }

  inline bool primitive_definition(std::string_view name)
  {
    return [&]<typename... T>([[maybe_unused]] std::tuple<T...> types) {
      return ((name == glz::name_v<T>) || ...);
    }(std::tuple<
             bool,
             char,
             signed char,
             unsigned char,
             short,
             unsigned short,
             int,
             unsigned int,
             long,
             unsigned long,
             long long,
             unsigned long long,
             float,
             double,
             long double,
             std::string,
             std::string_view,
             std::nullptr_t>{}) ||
      name == "ccf.adl.json" || name == "ccf.adl.json_schema";
  }

  class ComponentSchemas
  {
    const Json& source;
    const std::string& root_name;
    std::string_view type_name;
    Json& components;
    std::map<std::string, std::string> names;
    std::set<std::string> expanding;

    static Json with_constraints(Json target, Json node)
    {
      if (node.empty())
      {
        return target;
      }
      if (target.is_object())
      {
        bool compatible = true;
        for (const auto& [key, value] : target.items())
        {
          compatible &= !node.contains(key) || node[key] == value;
        }
        if (compatible)
        {
          node.update(target);
          return node;
        }
      }
      return Json{{"allOf", Json::array({target, node})}};
    }

    Json resolve(std::string reference)
    {
      auto target = source.at(Json::json_pointer(reference.substr(1)));
      std::set<std::string> aliases;
      while (target.is_object() && target.size() == 1 &&
             target.contains("$ref"))
      {
        if (!aliases.insert(reference).second)
        {
          throw std::logic_error("Cyclic schema alias: " + reference);
        }
        reference = target.at("$ref").get<std::string>();
        if (!reference.starts_with("#/$defs/"))
        {
          return target;
        }
        target = source.at(Json::json_pointer(reference.substr(1)));
      }
      const auto found = names.find(reference);
      const auto original_name =
        found == names.end() ? reference.substr(8) : found->second;
      if (primitive_definition(original_name))
      {
        return rewrite(std::move(target));
      }
      auto name = original_name;
      for (const auto* prefix : {"ccf.adl.", "ccf.openapi."})
      {
        if (name.starts_with(prefix))
        {
          name.erase(0, std::string_view(prefix).size());
          break;
        }
      }
      const auto key =
        original_name == type_name ? root_name : component_name(name);
      if (original_name != type_name && !expanding.contains(reference))
      {
        expanding.insert(reference);
        auto definition = rewrite(std::move(target));
        expanding.erase(reference);
        const auto existing = components.find(key);
        if (existing != components.end() && *existing != definition)
        {
          throw std::logic_error("Conflicting schema component: " + key);
        }
        components[key] = std::move(definition);
      }
      return Json{{"$ref", "#/components/schemas/" + key}};
    }

  public:
    ComponentSchemas(
      const Json& source_,
      const std::string& root_name_,
      std::string_view type_name_,
      Json& components_) :
      source(source_),
      root_name(root_name_),
      type_name(type_name_),
      components(components_)
    {
      const auto definitions = source.value("$defs", Json::object());
      for (const auto& [name, definition] : definitions.items())
      {
        names.emplace("#/$defs/" + escape_pointer(name), name);
      }
    }

    Json rewrite(Json schema)
    {
      if (schema.is_boolean())
      {
        return schema;
      }
      schema.erase("$defs");
      return transform_schema(std::move(schema), [&](Json node) {
        if (node.is_object())
        {
          node.erase("$defs");
        }
        if (!node.contains("$ref"))
        {
          return node;
        }
        const auto reference = node.at("$ref").get<std::string>();
        if (!reference.starts_with("#/$defs/"))
        {
          return node;
        }
        node.erase("$ref");
        return with_constraints(resolve(reference), std::move(node));
      });
    }
  };

  template <typename T>
  Json component_schema(
    std::string_view name, SchemaDocument* document = nullptr)
  {
    const auto key = component_name(name);
    try
    {
      auto schema = prepare_schema(native_schema<T>());
      if (document == nullptr)
      {
        return rebase_schema(schema, "#/components/schemas/" + key);
      }
      return ComponentSchemas(
               schema,
               key,
               glz::name_v<T>,
               document->document["components"]["schemas"])
        .rewrite(schema);
    }
    catch (const Json::out_of_range& error)
    {
      throw std::logic_error(
        "Invalid schema component '" + key + "': " + error.what());
    }
  }

  template <typename T>
  Json SchemaDocument::add_schema_component()
  {
    if constexpr (
      std::is_arithmetic_v<T> || std::is_same_v<T, std::string> ||
      std::is_same_v<T, Json> || std::is_same_v<T, ccf::ds::json::JsonSchema>)
    {
      return ccf::ds::json::schema_element<T>();
    }
    const auto name = component_name(ccf::ds::json::schema_name<T>());
    auto& schemas = document["components"]["schemas"];
    const auto inserted = schemas.emplace(name, Json::object());
    if (inserted.second)
    {
      auto& schema = inserted.first.value();
      if constexpr (Declared<T>)
      {
        schema = component_schema<T>(name, this);
      }
      else if constexpr (AdlSchemaComponents<T>)
      {
        add_schema_components(*this, schema, static_cast<const T*>(nullptr));
        schema = rebase_schema(schema, "#/components/schemas/" + name, true);
      }
      else if constexpr (AdlSchemaFill<T>)
      {
        fill_json_schema(schema, static_cast<const T*>(nullptr));
        schema = rebase_schema(schema, "#/components/schemas/" + name, true);
      }
      else
      {
        schema = component_schema<T>(name, this);
      }
    }
    return Json{{"$ref", "#/components/schemas/" + name}};
  }

  template <typename T>
  Json SchemaDocument::add_required_schema_component()
  {
    if constexpr (ccf::nonstd::is_specialization<T, std::optional>::value)
    {
      return Json{
        {"anyOf",
         Json::array(
           {add_schema_component<typename T::value_type>(),
            Json{{"type", "null"}}})}};
    }
    else
    {
      return add_schema_component<T>();
    }
  }

}

namespace glz::detail
{
  template <ccf::json::detail::DomAdapter T>
    requires(!array_t<T>)
  struct to_json_schema<T> : ccf::json::detail::AdlSchema<T>
  {};

  template <ccf::json::detail::DomAdapter T>
    requires array_t<T>
  struct to_json_schema<T> : ccf::json::detail::AdlSchema<T>
  {};
}

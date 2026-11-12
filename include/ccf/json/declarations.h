// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/json/metadata.h"
#include "ccf/json/schema.h"

#include <glaze/json/read.hpp>
#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ccf::json::detail
{
  template <typename Owners, typename Fields>
  struct DefaultOwners;

  template <typename... Owners>
  struct DefaultOwners<std::tuple<Owners...>, std::tuple<>>
  {
    using Type = std::tuple<Owners...>;
  };

  template <typename... Owners, typename F, typename... Rest>
  struct DefaultOwners<std::tuple<Owners...>, std::tuple<F, Rest...>>
    : DefaultOwners<
        std::conditional_t<
          F::policy == Presence::Optional &&
            !(std::is_same_v<typename F::DefaultType, Owners> || ...),
          std::tuple<Owners..., typename F::DefaultType>,
          std::tuple<Owners...>>,
        std::tuple<Rest...>>
  {};

  template <typename Owners>
  struct DefaultCache;

  template <typename... Owners>
  struct DefaultCache<std::tuple<Owners...>>
  {
    std::tuple<std::optional<Owners>...> values;
  };

  template <typename T>
  Json to_dom_value(const T& value)
  {
    if constexpr (std::is_constructible_v<Json, const T&>)
    {
      return Json(value);
    }
    else
    {
      return Json::parse(ccf::json::write(value));
    }
  }

  template <typename T>
  T from_dom_value(const Json& value)
  {
    if constexpr (requires { value.template get<T>(); })
    {
      return value.template get<T>();
    }
    else
    {
      return ccf::json::read<T>(value.dump());
    }
  }

  template <typename T>
  Json write(const T& value)
  {
    return Json::parse(ccf::json::write(value));
  }

  template <typename T>
  void read_into(T& value, const std::string& input)
  {
    ccf::json::read(value, input);
  }

  template <typename T>
  T read(const std::string& input)
  {
    T value{};
    read_into(value, input);
    return value;
  }

  template <typename T, typename F>
  void read_dom_field(const Json& j, T& value, F field)
  {
    const auto it = j.find(field.name);
    if (it == j.end())
    {
      if constexpr (F::policy == Presence::Required)
      {
        throw ccf::JsonParseError(
          "Missing required field '" + std::string(field.name) + "' in object");
      }
      return;
    }
    using Member = std::remove_cvref_t<decltype(value.*F::member)>;
    if constexpr (F::policy == Presence::Required)
    {
      try
      {
        value.*F::member = from_dom_value<Member>(*it);
      }
      catch (ccf::JsonParseError& error)
      {
        error.pointer_elements.emplace_back(field.name);
        throw;
      }
    }
    else
    {
      value.*F::member = from_dom_value<Member>(*it);
    }
  }

  template <Declared T>
  void to_dom(Json& j, const T& value)
  {
    if constexpr (std::is_enum_v<T>)
    {
      const auto label = enum_label(value);
      if (!label)
      {
        throw ccf::JsonParseError(
          "Enum value has no specified JSON conversion");
      }
      j = *label;
    }
    else
    {
      if (!j.is_object())
      {
        j = Json::object();
      }
      using Fields =
        std::remove_cvref_t<decltype(Metadata<T>::declaration.fields)>;
      DefaultCache<typename DefaultOwners<std::tuple<>, Fields>::Type>
        defaults{};
      std::apply(
        [&](auto... field) {
          const auto write_field = [&](auto f) {
            using F = decltype(f);
            const auto& member = value.*F::member;
            if constexpr (F::policy == Presence::Optional)
            {
              auto& owner = std::get<std::optional<typename F::DefaultType>>(
                defaults.values);
              if (!owner.has_value())
              {
                owner.emplace();
              }
              if (!(member != (*owner).*F::member))
              {
                return;
              }
            }
            j[f.name] = to_dom_value(member);
          };
          (write_field(field), ...);
        },
        Metadata<T>::declaration.fields);
    }
  }

  template <Declared T>
  void from_dom(const Json& j, T& value)
  {
    if constexpr (std::is_enum_v<T>)
    {
      if (!j.is_string())
      {
        throw ccf::JsonParseError("Expected enum string");
      }
      const auto& label = j.get_ref<const std::string&>();
      std::optional<T> parsed;
      for (const auto& [entry, name] : Metadata<T>::declaration.entries)
      {
        if (label == name)
        {
          parsed = entry;
          break;
        }
      }
      if (!parsed)
      {
        throw ccf::JsonParseError("Unknown enum string");
      }
      value = *parsed;
    }
    else
    {
      if (!j.is_object())
      {
        throw ccf::JsonParseError("Expected object");
      }
      std::apply(
        [&](auto... field) { (read_dom_field(j, value, field), ...); },
        Metadata<T>::declaration.fields);
    }
  }
}

#define CCF_JSON_REQUIRED_FOR_JSON_NEXT(TYPE, FIELD) \
  ccf::json::detail:: \
    Field<&TYPE::FIELD, ccf::json::detail::Presence::Required>{#FIELD},
#define CCF_JSON_REQUIRED_FOR_JSON_FINAL(TYPE, FIELD) \
  ccf::json::detail:: \
    Field<&TYPE::FIELD, ccf::json::detail::Presence::Required> \
  { \
    #FIELD \
  }
#define CCF_JSON_OPTIONAL_FOR_JSON_NEXT(TYPE, FIELD) \
  ccf::json::detail:: \
    Field<&TYPE::FIELD, ccf::json::detail::Presence::Optional>{#FIELD},
#define CCF_JSON_OPTIONAL_FOR_JSON_FINAL(TYPE, FIELD) \
  ccf::json::detail:: \
    Field<&TYPE::FIELD, ccf::json::detail::Presence::Optional> \
  { \
    #FIELD \
  }
#define CCF_JSON_ALLOW_MISSING_FOR_JSON_NEXT(TYPE, FIELD) \
  ccf::json::detail:: \
    Field<&TYPE::FIELD, ccf::json::detail::Presence::AllowMissing>{#FIELD},
#define CCF_JSON_ALLOW_MISSING_FOR_JSON_FINAL(TYPE, FIELD) \
  ccf::json::detail:: \
    Field<&TYPE::FIELD, ccf::json::detail::Presence::AllowMissing> \
  { \
    #FIELD \
  }

#define CCF_JSON_REQUIRED(...) \
  std::tuple \
  { \
    __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_JSON_REQUIRED, T, __VA_ARGS__)) \
  }
#define CCF_JSON_OPTIONAL(...) \
  std::tuple \
  { \
    __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_JSON_OPTIONAL, T, __VA_ARGS__)) \
  }
#define CCF_JSON_ALLOW_MISSING(...) \
  std::tuple \
  { \
    __VA_OPT__(_FOR_JSON_COUNT_NN(__VA_ARGS__)(POP1)( \
      CCF_JSON_ALLOW_MISSING, T, __VA_ARGS__)) \
  }
#define CCF_JSON_NAMED(POLICY, FIELD, NAME) \
  std::tuple \
  { \
    ccf::json::detail::Field<&T::FIELD, ccf::json::detail::Presence::POLICY> \
    { \
      NAME \
    } \
  }
#define CCF_JSON_BASE(BASE) \
  ccf_json_declaration(static_cast<const BASE*>(nullptr)).fields

// The same field declaration drives DOM conversion, direct I/O, and schemas.
#define CCF_JSON_FIELDS(TYPE, ...) \
  inline constexpr auto ccf_json_declaration(const TYPE*) \
  { \
    using T [[maybe_unused]] = TYPE; \
    return ccf::json::detail::declare<T>(#TYPE, std::tuple_cat(__VA_ARGS__)); \
  }

#define CCF_JSON_SCHEMA(TYPE) \
  inline std::string schema_name(const TYPE*) \
  { \
    return #TYPE; \
  } \
  template <typename U = TYPE> \
  inline void fill_json_schema(ccf::json::detail::Json& j, const TYPE*) \
  { \
    auto schema = ccf::json::detail::standalone_schema<U>(); \
    if (j.contains("title")) \
    { \
      schema["title"] = j["title"]; \
    } \
    j = std::move(schema); \
  } \
  template <typename Doc> \
  void add_schema_components( \
    Doc&, ccf::json::detail::Json& j, const TYPE* tag) \
  { \
    j = ccf::json::detail::component_schema<TYPE>(schema_name(tag)); \
  }

#define CCF_JSON_CONVERSIONS(TYPE) \
  template <typename U = TYPE> \
  inline void to_json(ccf::json::detail::Json& j, const TYPE& value) \
  { \
    ccf::json::detail::to_dom<U>(j, value); \
  } \
  template <typename U = TYPE> \
  inline void from_json(const ccf::json::detail::Json& j, TYPE& value) \
  { \
    ccf::json::detail::from_dom<U>(j, value); \
  } \
  CCF_JSON_SCHEMA(TYPE)

#define CCF_JSON_TYPE(TYPE, ...) \
  CCF_JSON_FIELDS(TYPE, __VA_ARGS__) \
  CCF_JSON_CONVERSIONS(TYPE) \
  static_assert(true, "Semicolon required")

#define CCF_JSON_ENUM_SCHEMA(TYPE) \
  template <typename U = TYPE> \
  inline void fill_enum_schema(ccf::json::detail::Json& j, const TYPE*) \
  { \
    auto schema = ccf::json::detail::standalone_schema<U>(); \
    if (j.contains("title")) \
    { \
      schema["title"] = j["title"]; \
    } \
    j = std::move(schema); \
  }

#define CCF_JSON_ENUM_CONVERSIONS(TYPE) \
  template <typename BasicJsonType, typename U = TYPE> \
  inline void to_json(BasicJsonType& j, const TYPE& value) \
  { \
    const auto label = ccf::json::detail::enum_label<U>(value); \
    if (!label) \
    { \
      throw ccf::JsonParseError( \
        "Enum value has no specified JSON conversion"); \
    } \
    j = *label; \
  } \
  template <typename BasicJsonType, typename U = TYPE> \
  inline void from_json(const BasicJsonType& j, TYPE& value) \
  { \
    for (const auto& [entry, label] : \
         ccf::json::detail::Metadata<U>::declaration.entries) \
    { \
      if (j == BasicJsonType(label)) \
      { \
        value = entry; \
        return; \
      } \
    } \
    throw ccf::JsonParseError("Unknown enum string"); \
  } \
  CCF_JSON_SCHEMA(TYPE) \
  CCF_JSON_ENUM_SCHEMA(TYPE)

#define CCF_JSON_ENUM(TYPE, ...) \
  inline constexpr auto ccf_json_declaration(const TYPE*) \
  { \
    return ccf::json::detail::declare_enum<TYPE>(#TYPE, __VA_ARGS__); \
  } \
  CCF_JSON_ENUM_CONVERSIONS(TYPE) \
  static_assert(true, "Semicolon required")

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/json/metadata.h"
#include "ccf/json/primitives.h"

#include <version>

// Clang 19 raised this feature macro to expose libstdc++'s existing expected.
// Load it for the older supported pairing without changing other headers.
#if defined(__clang__) && defined(__GLIBCXX__)
#  if __clang_major__ == 18 && _GLIBCXX_RELEASE == 13 && \
    __cplusplus > 202002L && __cpp_concepts == 201907L && \
    !defined(__cpp_lib_expected)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wbuiltin-macro-redefined"
#    pragma push_macro("__cpp_concepts")
#    undef __cpp_concepts
#    define __cpp_concepts 202002L
// A prior include may have set the guard without defining std::expected.
#    ifdef _GLIBCXX_EXPECTED
#      undef _GLIBCXX_EXPECTED
#    endif
#    include <expected>
#    pragma pop_macro("__cpp_concepts")
#    pragma clang diagnostic pop
#  endif
#endif

#include <glaze/json/read.hpp>
#include <glaze/json/write.hpp>
#include <map>
#include <unordered_map>

namespace ccf::json::detail
{
  using Json = nlohmann::json;

  template <Declared T>
  constexpr auto glaze_fields()
  {
    constexpr auto declaration = Metadata<T>::declaration;
    if constexpr (std::is_enum_v<T>)
    {
      return [&]<size_t... I>(std::index_sequence<I...>) {
        return std::apply(
          [](auto... args) { return glz::enumerate(args...); },
          std::tuple_cat(std::tuple{
            declaration.entries[I].second, declaration.entries[I].first}...));
      }(std::make_index_sequence<declaration.entries.size()>{});
    }
    else
    {
      return std::apply(
        [](auto... field) {
          return std::apply(
            [](auto... args) { return glz::object(args...); },
            std::tuple_cat(std::tuple{field.name, decltype(field)::member}...));
        },
        declaration.fields);
    }
  }

  template <Declared T>
  std::optional<std::string_view> enum_label(T value)
    requires std::is_enum_v<T>
  {
    for (const auto& [entry, label] : Metadata<T>::declaration.entries)
    {
      if (entry == value)
      {
        return label;
      }
    }
    return std::nullopt;
  }

  // Avoid finding nlohmann's generic conversions through the JSON argument.
  struct AdlJsonProbe
  {
    operator Json&() const;
  };

  template <typename T>
  concept AdlJson =
    requires(const T& value) { to_json(AdlJsonProbe{}, value); };

  template <typename T>
  inline constexpr bool standard_container = false;

  template <typename T>
  inline constexpr bool standard_container<std::optional<T>> = true;

  template <typename T, typename Allocator>
  inline constexpr bool standard_container<std::vector<T, Allocator>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::map<Args...>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::unordered_map<Args...>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::set<Args...>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::unordered_set<Args...>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::tuple<Args...>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::pair<Args...>> = true;

  template <typename... Args>
  inline constexpr bool standard_container<std::variant<Args...>> = true;

  template <typename T, size_t N>
  inline constexpr bool standard_container<std::array<T, N>> = true;

  template <typename T>
  inline constexpr bool legacy_map = false;

  template <typename Key, typename Value, typename... Args>
  inline constexpr bool legacy_map<std::map<Key, Value, Args...>> =
    !std::same_as<Key, std::string> &&
    std::is_constructible_v<Json, const std::map<Key, Value, Args...>&>;

  template <typename Key, typename Value, typename... Args>
  inline constexpr bool legacy_map<std::unordered_map<Key, Value, Args...>> =
    !std::same_as<Key, std::string> &&
    std::
      is_constructible_v<Json, const std::unordered_map<Key, Value, Args...>&>;

  // An explicit ADL contract takes precedence over aggregate reflection.
  // Standard containers keep native Glaze I/O, except the CCF byte wire format.
  template <typename T>
  concept AdlLeaf = !Declared<T> && std::is_class_v<T> &&
    !nlohmann::detail::is_basic_json<T>::value && !standard_container<T> &&
    AdlJson<T>;

  template <typename T>
  concept DomAdapter = std::same_as<T, Json> ||
    std::same_as<T, std::vector<uint8_t>> || legacy_map<T> || AdlLeaf<T>;
}

namespace glz
{
  template <ccf::json::detail::Declared T>
  struct meta<T> : ccf::json::detail::Metadata<T>
  {
    static constexpr auto value = ccf::json::detail::glaze_fields<T>();
    static constexpr bool custom_write = std::is_enum_v<T>;

    static bool skip_if(
      const auto& member,
      std::string_view key,
      [[maybe_unused]] const glz::meta_context& context)
    {
      // Glaze's field callback has no per-object storage for default owners.
      // Do not cache these globally: default constructors may be stateful.
      return std::apply(
        [&](auto... field) {
          return (meta::skip_field(member, key, field) || ...);
        },
        meta::declaration.fields);
    }
  };

  template <ccf::json::detail::DomAdapter T>
  struct meta<T>
  {
    static constexpr bool glaze_reflect = false;
    static constexpr bool custom_read = true;
    static constexpr bool custom_write = true;
  };

  template <>
  struct meta<std::vector<uint8_t>>
  {
    static constexpr bool glaze_reflect = false;
    static constexpr std::string_view name = "std::vector<uint8_t>";
    static constexpr bool custom_read = true;
    static constexpr bool custom_write = true;
  };

  template <typename Key, typename Value, typename... Args>
    requires ccf::json::detail::legacy_map<std::map<Key, Value, Args...>>
  struct meta<std::map<Key, Value, Args...>>
  {
    static constexpr bool glaze_reflect = false;
    static constexpr bool custom_read = true;
    static constexpr bool custom_write = true;
  };

  template <typename Key, typename Value>
    requires ccf::json::detail::legacy_map<std::map<Key, Value>>
  struct meta<std::map<Key, Value>>
  {
    static constexpr bool glaze_reflect = false;
    static constexpr bool custom_read = true;
    static constexpr bool custom_write = true;
  };

  template <typename Key, typename Value, typename... Args>
    requires ccf::json::detail::legacy_map<
      std::unordered_map<Key, Value, Args...>>
  struct meta<std::unordered_map<Key, Value, Args...>>
  {
    static constexpr bool glaze_reflect = false;
    static constexpr bool custom_read = true;
    static constexpr bool custom_write = true;
  };

  // Glaze normally writes unmapped enums as numbers; CCF rejects them.
  template <ccf::json::detail::Declared T>
    requires std::is_enum_v<T>
  struct to<JSON, T>
  {
    static constexpr bool can_error = true;

    template <auto Options>
    static void op(T value, is_context auto&& context, auto&&... args)
    {
      const auto label = ccf::json::detail::enum_label(value);
      if (!label)
      {
        context.error = error_code::unexpected_enum;
        return;
      }
      serialize<JSON>::op<Options>(
        *label, context, std::forward<decltype(args)>(args)...);
    }
  };

  template <ccf::json::detail::DomAdapter T>
  struct to<JSON, T>
  {
    template <auto Options>
    static void op(const T& value, is_context auto&& context, auto&&... args)
    {
      const raw_json raw{ccf::json::detail::Json(value).dump()};
      serialize<JSON>::op<Options>(
        raw, context, std::forward<decltype(args)>(args)...);
    }
  };

  template <ccf::json::detail::DomAdapter T>
  struct from<JSON, T>
  {
    template <auto Options>
    static void op(T& value, is_context auto&& context, auto& it, auto end)
    {
      raw_json_view raw;
      parse<JSON>::op<Options>(raw, context, it, end);
      if (context.error != error_code::none)
      {
        return;
      }
      const auto dom = ccf::parse_json_safe(raw.str);
      if constexpr (std::same_as<T, ccf::json::detail::Json>)
      {
        value = dom;
      }
      else if constexpr (std::same_as<T, std::vector<uint8_t>>)
      {
        value = dom.template get<T>();
      }
      else
      {
        dom.get_to(value);
      }
    }
  };
}

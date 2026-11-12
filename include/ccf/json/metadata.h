// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ccf::json::detail
{
  enum class Presence : std::uint8_t
  {
    Required,
    Optional,
    AllowMissing
  };

  template <auto Member, Presence Policy, typename Defaults = void>
  struct Field
  {
    using DefaultType = Defaults;
    std::string_view name;
    static constexpr auto member = Member;
    static constexpr auto policy = Policy;
  };

  template <typename T, typename Fields, typename Entries = std::tuple<>>
  struct Declaration
  {
    using Type = T;
    std::string_view name;
    Fields fields;
    Entries entries;
  };

  template <typename T, typename Fields>
  constexpr auto declare(std::string_view name, Fields fields)
  {
    const auto resolved = std::apply(
      [](auto... field) {
        const auto bind_default = [](auto f) {
          using F = decltype(f);
          if constexpr (
            F::policy == Presence::Optional &&
            std::is_void_v<typename F::DefaultType>)
          {
            return Field<F::member, F::policy, T>{f.name};
          }
          else
          {
            return f;
          }
        };
        return std::tuple{bind_default(field)...};
      },
      fields);
    return Declaration<T, std::remove_cvref_t<decltype(resolved)>>{
      name, resolved, {}};
  }

  template <typename T, size_t N>
  constexpr auto declare_enum(
    std::string_view name,
    const std::array<std::pair<T, std::string_view>, N>& entries)
  {
    return Declaration<T, std::tuple<>, std::remove_cvref_t<decltype(entries)>>{
      name, {}, entries};
  }

  template <typename T, typename... Args>
  constexpr auto declare_enum(std::string_view name, Args... args)
  {
    static_assert(sizeof...(Args) % 2 == 0, "Expected enum label/value pairs");
    const auto values = std::tuple{args...};
    return [&]<size_t... I>(std::index_sequence<I...>) {
      return declare_enum<T>(
        name,
        std::array<std::pair<T, std::string_view>, sizeof...(I)>{
          std::pair<T, std::string_view>{
            std::get<(2 * I) + 1>(values), std::get<2 * I>(values)}...});
    }(std::make_index_sequence<sizeof...(Args) / 2>{});
  }

  template <typename T>
  concept Declared = requires {
    requires std::is_same_v<
      typename decltype(ccf_json_declaration(
        static_cast<const T*>(nullptr)))::Type,
      T>;
  };

  template <Declared T>
  struct Metadata
  {
    static constexpr auto declaration =
      ccf_json_declaration(static_cast<const T*>(nullptr));
    static constexpr auto name = declaration.name;

    static constexpr bool requires_key(
      std::string_view key, [[maybe_unused]] bool nullable)
    {
      return std::apply(
        [key](auto... field) {
          return (
            (key == field.name &&
             decltype(field)::policy == Presence::Required) ||
            ...);
        },
        declaration.fields);
    }

    template <typename Value, typename F>
    static bool skip_field(const Value& member, std::string_view key, F field)
    {
      if constexpr (F::policy == Presence::Optional)
      {
        using MemberType =
          std::remove_cvref_t<decltype(std::declval<T>().*F::member)>;
        if constexpr (std::is_same_v<Value, MemberType>)
        {
          if (key == field.name)
          {
            using DefaultType = std::conditional_t<
              std::is_void_v<typename F::DefaultType>,
              T,
              typename F::DefaultType>;
            const DefaultType defaults{};
            return !(member != defaults.*F::member);
          }
        }
      }
      return false;
    }
  };

}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

/**
 * This file defines various type traits and utils that are not available in the
 * standard library. Some are added in future versions of the standard library,
 * some are proposed, some are purely custom. They are defined here to avoid
 * repetition in other locations.
 */
namespace nonstd
{
  /** is_specialization detects type-specialized templates. This does not work
   * for value-dependent types (eg - std::array)
   */
  template <typename T, template <typename...> class U>
  struct is_specialization : std::false_type
  {};

  template <template <typename...> class T, typename... Args>
  struct is_specialization<T<Args...>, T> : std::true_type
  {};

  /** Similar to is_specialization, but for detecting std::array specifically
   */
  template <typename T>
  struct is_std_array : std::false_type
  {};

  template <typename T, size_t N>
  struct is_std_array<std::array<T, N>> : public std::true_type
  {};

  /** Similar to is_specialization, but for detecting std::vector specifically
   */
  template <typename T>
  struct is_std_vector : std::false_type
  {};

  template <typename T>
  struct is_std_vector<std::vector<T>> : public std::true_type
  {};

  /** dependent_false produces a static, compile-time false, dependent on a
   * specific type or value instantiation. This is useful for producing a
   * static_assert which will fail only when invalid paths are called, but
   * allows compilation otherwise
   */
  template <typename T>
  struct dependent_false : public std::false_type
  {};

  template <typename T>
  static constexpr bool dependent_false_v = dependent_false<T>::value;

  template <typename T, T>
  struct value_dependent_false : public std::false_type
  {};

  template <typename T, T t>
  static constexpr bool value_dependent_false_v = dependent_false<T>::value;

  /** split is based on Python's str.split
   */
  static inline std::vector<std::string_view> split(
    const std::string_view& s,
    const std::string_view& separator = " ",
    size_t max_split = SIZE_MAX)
  {
    std::vector<std::string_view> result;

    auto separator_end = 0;
    auto next_separator_start = s.find(separator);
    while (next_separator_start != std::string_view::npos &&
           result.size() < max_split)
    {
      result.push_back(
        s.substr(separator_end, next_separator_start - separator_end));

      separator_end = next_separator_start + separator.size();
      next_separator_start = s.find(separator, separator_end);
    }

    result.push_back(s.substr(separator_end));

    return result;
  }

  /* split_1 wraps split and allows writing things like:
   * auto [host, port] = nonstd::split_1("1.2.3.4:8000", ":")
   */
  static inline std::tuple<std::string_view, std::string_view> split_1(
    const std::string_view& s, const std::string_view& separator)
  {
    const auto v = split(s, separator, 1);
    if (v.size() == 1)
    {
      // If separator is not present, return {s, ""};
      return std::make_tuple(v[0], "");
    }

    return std::make_tuple(v[0], v[1]);
  }

  /** Similar to split, but splits first from the end rather than the beginning.
   * This means the results are returned in reverse order, and if max_split is
   * specified then only the final N entries will be kept.
   * split("A:B:C", ":", 1) => ["A", "B:C"]
   * rsplit("A:B:C", ":", 1) => ["C", "A:B"]
   */
  static inline std::vector<std::string_view> rsplit(
    const std::string_view& s,
    const std::string_view& separator = " ",
    size_t max_split = SIZE_MAX)
  {
    std::vector<std::string_view> result;

    auto prev_separator_start = s.size();
    auto next_separator_start = s.rfind(separator);
    while (next_separator_start != std::string_view::npos &&
           result.size() < max_split)
    {
      auto separator_end = next_separator_start + separator.size();

      result.push_back(
        s.substr(separator_end, prev_separator_start - separator_end));

      prev_separator_start = next_separator_start;

      if (next_separator_start == 0)
      {
        break;
      }
      else
      {
        next_separator_start = s.rfind(separator, prev_separator_start - 1);
      }
    }

    result.push_back(s.substr(0, prev_separator_start));

    return result;
  }

  /* rsplit_1 wraps rsplit _and reverses the result order_ and allows writing
   * things like:
   * auto [host, port] = nonstd::rsplit_1("[1:2:3:4]:8000", ":")
   */
  static inline std::tuple<std::string_view, std::string_view> rsplit_1(
    const std::string_view& s, const std::string_view& separator)
  {
    const auto v = rsplit(s, separator, 1);
    if (v.size() == 1)
    {
      // If separator is not present, return {"", s};
      return std::make_tuple("", v[0]);
    }

    return std::make_tuple(v[1], v[0]);
  }

  /** These convert strings to upper or lower case, in-place
   */
  static inline void to_upper(std::string& s)
  {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
      return std::toupper(c);
    });
  }

  static inline void to_lower(std::string& s)
  {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
      return std::tolower(c);
    });
  }

  // Iterators for map-keys and map-values
  template <typename TMapIterator>
  class KeyIterator : public TMapIterator
  {
  public:
    KeyIterator() : TMapIterator() {}
    KeyIterator(TMapIterator it) : TMapIterator(it) {}

    using Key =
      typename std::iterator_traits<TMapIterator>::value_type::first_type;
    using value_type = Key;

    Key* operator->()
    {
      return TMapIterator::operator->()->first;
    }

    Key operator*()
    {
      return TMapIterator::operator*().first;
    }
  };

  template <typename TMapIterator>
  class ValueIterator : public TMapIterator
  {
  public:
    ValueIterator() : TMapIterator() {}
    ValueIterator(TMapIterator it) : TMapIterator(it) {}

    using Value =
      typename std::iterator_traits<TMapIterator>::value_type::second_type;
    using value_type = Value;

    Value* operator->()
    {
      return TMapIterator::operator->()->second;
    }

    Value operator*()
    {
      return TMapIterator::operator*().second;
    }
  };
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <array>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

/**
 * This file defines various type traits and utils that are not available in the
 * standard library. Some are added in C++20, some are proposed, some are purely
 * custom. They are defined here to avoid repetition in other locations
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

  /** dependent_false produces a static, compile-time false, dependent on a
   * specific type or value instantiation. This is useful for producing a
   * static_assert which will fail only when invalid paths are called, but
   * allows compilation otherwise
   */
  template <typename T, T = T{}>
  struct dependent_false : public std::false_type
  {};

  template <typename T, T t = T{}>
  static constexpr bool dependent_false_v = dependent_false<T, t>::value;

  /** remove_cvref combines remove_cv and remove_reference - this is present in
   * C++20
   */
  template <class T>
  struct remove_cvref
  {
    typedef std::remove_cv_t<std::remove_reference_t<T>> type;
  };

  template <class T>
  using remove_cvref_t = typename remove_cvref<T>::type;

  /** Split a string at each instance of the given delimitor. Returns
   * string_views over the input string, exclusive of the delimiter
   *
   * ie:
   * split_string("hello world", ' ') -> ["hello", "world"]
   * split_string("hello", ' ') -> ["hello"]
   * split_string(" hello ", ' ') -> ["", ",hello", ""]
   * split_string("/some/url/path", '/') -> ["", "some", "url", "path"]
   *
   */
  inline std::vector<std::string_view> split_string(
    const std::string& s, char delimiter)
  {
    std::vector<std::string_view> views;
    const auto data = s.c_str();

    auto view_start = 0;
    auto next_delim = s.find_first_of(delimiter, view_start);
    while (next_delim != std::string::npos)
    {
      views.emplace_back(data + view_start, next_delim - view_start);
      view_start = next_delim + 1;
      next_delim = s.find_first_of(delimiter, view_start);
    }
    views.emplace_back(data + view_start, s.size() - view_start);
    return views;
  }
}
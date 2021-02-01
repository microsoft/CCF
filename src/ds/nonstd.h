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

  /** more generic std::string member functions are present in C++20
   */
  static inline bool starts_with(
    const std::string& s, const std::string& prefix)
  {
    return s.rfind(prefix, 0) == 0;
  }

  static inline bool ends_with(const std::string& s, const std::string& suffix)
  {
    return s.size() >= suffix.size() &&
      s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
  }

  /** converts strings to upper or lower case, in-place
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

  static inline std::string remove_prefix(
    const std::string& s, const std::string& prefix)
  {
    if (starts_with(s, prefix))
    {
      return s.substr(prefix.size());
    }

    return s;
  }
}
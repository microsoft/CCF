#pragma once

#include <locale>
#include <sstream>
#include <string>

// This file provides alternative implementations for converting strings to
// double values. This addresses the fact that std::from_chars is not
// available in all standard libraries, and that some implementations of
// std::from_chars do not support floating-point types.
//
// We support three different implementations:
//
// 1. std::from_chars (C++17) - preferred if available, as indicated by
//                              the VALIJSON_HAS_STD_FROM_CHARS or compiler-
//                              specific preprocessor defines
//
// 2. fast_float::from_chars  - if VALIJSON_HAS_FAST_FLOAT_FROM_CHARS is
//                              defined, then we will use the fast_float
//                              library's implementation of from_chars
//
// 3. std::istringstream      - fallback if neither of the above are available
//

// attempt detection of std::from_chars support
#ifndef VALIJSON_HAS_STD_FROM_CHARS
#  if defined(_MSC_VER) && _MSC_VER >= 1915
#    define VALIJSON_HAS_STD_FROM_CHARS 1
#  elif defined(_LIBCPP_VERSION) && _LIBCPP_VERSION >= 200000
#    define VALIJSON_HAS_STD_FROM_CHARS 1
#  elif defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE >= 11
#    define VALIJSON_HAS_STD_FROM_CHARS 1
#  else
#    define VALIJSON_HAS_STD_FROM_CHARS 0
#  endif
#endif

// include the appropriate header for the available implementation
#if VALIJSON_HAS_STD_FROM_CHARS
#  include <charconv>
#elif defined(VALIJSON_HAS_FAST_FLOAT_FROM_CHARS)
#  include <fast_float/fast_float.h>
#endif

namespace valijson {
namespace internal {

inline bool parseDouble(const std::string &input, double &result)
{
#if VALIJSON_HAS_STD_FROM_CHARS
    const char *begin = input.data();
    const char *end = begin + input.length();
    double value;
    const auto conversion = std::from_chars(begin, end, value);
    if (conversion.ec != std::errc() || conversion.ptr != end) {
        return false;
    }
#elif defined(VALIJSON_HAS_FAST_FLOAT_FROM_CHARS)
    const char *begin = input.data();
    const char *end = begin + input.length();
    double value;
    const auto conversion = fast_float::from_chars(begin, end, value);
    if (conversion.ec != std::errc() || conversion.ptr != end) {
        return false;
    }
#else
    std::istringstream stream(input);
    stream.imbue(std::locale::classic());
    stream >> std::noskipws;

    double value;
    if (!(stream >> value) || stream.peek() != std::char_traits<char>::eof()) {
        return false;
    }
#endif

    result = value;
    return true;
}

} // namespace internal
} // namespace valijson

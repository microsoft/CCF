#pragma once

#include <cstddef>
#include <string>

namespace valijson {
namespace internal {

/**
 * @brief  Check whether a string is an Internet host name, as defined in
 *         RFC 1123, section 2.1
 *
 * A host name consists of labels separated by dots. Each label consists of one
 * to 63 letters, digits and hyphens, and starts and ends with a letter or a
 * digit. A host name has at most 255 characters, and does not end with a dot.
 *
 * Labels encoded with Punycode (A-labels) are only checked against this
 * syntax.
 *
 * @param  s  string to check, which may contain embedded null bytes
 *
 * @return \c true if \p s is a host name
 */
inline bool isHostname(const std::string &s)
{
    if (s.empty() || s.size() > 255) {
        return false;
    }

    size_t labelLength = 0;
    char previous = '.';
    for (const char c : s) {
        if (c == '.') {
            // Labels must not be empty, or end with a hyphen
            if (labelLength == 0 || previous == '-') {
                return false;
            }
            labelLength = 0;
        } else {
            const bool isLetterOrDigit = (c >= 'a' && c <= 'z') ||
                    (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
            if (!isLetterOrDigit && c != '-') {
                return false;
            }

            // Labels must start with a letter or digit
            if (labelLength == 0 && c == '-') {
                return false;
            }

            if (++labelLength > 63) {
                return false;
            }
        }

        previous = c;
    }

    // The last label must not be empty, which rules out a trailing dot, or
    // end with a hyphen
    return labelLength > 0 && previous != '-';
}

}  // namespace internal
}  // namespace valijson

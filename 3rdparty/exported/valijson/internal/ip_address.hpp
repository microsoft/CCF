#pragma once

#include <cstddef>
#include <string>

namespace valijson {
namespace internal {

/**
 * @brief  Check whether part of a string is an IPv4 address in dotted decimal
 *         notation
 *
 * This is used for the 'ipv4' format, and for the mixed form of IPv6
 * addresses. Each of the four parts consists of one to three decimal digits,
 * with a value of at most 255, as in the dotted-quad syntax of RFC 2673,
 * section 3.2.
 *
 * The dotted-quad syntax permits leading zeros. The dec-octet syntax of
 * RFC 3986, section 3.2.2, which applies to IPv4 addresses embedded in IPv6
 * addresses, does not.
 *
 * @param  s                  string to check, which may contain embedded null
 *                            bytes
 * @param  begin              index of the first character to check
 * @param  end                index after the last character to check
 * @param  allowLeadingZeros  whether a part may have leading zeros
 *
 * @return \c true if the characters from \p begin to \p end form an IPv4
 *         address
 */
inline bool isIpv4DottedQuad(const std::string &s, size_t begin, size_t end,
                             bool allowLeadingZeros = true)
{
    size_t i = begin;
    for (int part = 0; part < 4; part++) {
        if (part > 0) {
            if (i == end || s[i] != '.') {
                return false;
            }
            i++;
        }

        const size_t digitsBegin = i;
        int value = 0;
        while (i < end && s[i] >= '0' && s[i] <= '9' && i - digitsBegin < 3) {
            value = value * 10 + (s[i] - '0');
            i++;
        }

        if (i == digitsBegin || value > 255) {
            return false;
        }

        if (!allowLeadingZeros && s[digitsBegin] == '0' &&
            i - digitsBegin > 1) {
            return false;
        }
    }

    return i == end;
}

/**
 * @brief  Check whether a string is an IPv6 address, as defined in RFC 4291,
 *         section 2.2
 *
 * An address consists of eight groups of one to four hexadecimal digits,
 * separated by colons. One sequence of one or more groups may be replaced by
 * '::', and the last two groups may be written as an IPv4 address in dotted
 * decimal notation. As in the IPv6address syntax of RFC 3986, section 3.2.2,
 * the parts of an embedded IPv4 address must not have leading zeros.
 *
 * @param  s  string to check, which may contain embedded null bytes
 *
 * @return \c true if \p s is an IPv6 address
 */
inline bool isIpv6Address(const std::string &s)
{
    const auto isHexDigit = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };

    const size_t end = s.size();
    size_t i = 0;
    size_t groups = 0;
    bool compressed = false;

    // An address may only start with a colon if it starts with '::'
    if (end >= 2 && s[0] == ':' && s[1] == ':') {
        compressed = true;
        i = 2;
    } else if (end == 0 || s[0] == ':') {
        return false;
    }

    while (i < end) {
        const size_t groupBegin = i;
        while (i < end && isHexDigit(s[i])) {
            i++;
        }

        // An IPv4 address may only appear at the end, in place of two groups
        if (i < end && s[i] == '.') {
            if (!isIpv4DottedQuad(s, groupBegin, end, false)) {
                return false;
            }
            groups += 2;
            break;
        }

        const size_t digits = i - groupBegin;
        if (digits == 0 || digits > 4) {
            return false;
        }
        groups++;

        if (i == end) {
            break;
        }

        // Each group is followed by a colon, or by '::' at most once
        if (s[i] != ':') {
            return false;
        }
        i++;
        if (i < end && s[i] == ':') {
            if (compressed) {
                return false;
            }
            compressed = true;
            i++;
        } else if (i == end) {
            return false;
        }
    }

    // '::' stands for at least one group
    return compressed ? groups <= 7 : groups == 8;
}

}  // namespace internal
}  // namespace valijson

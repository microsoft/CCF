#pragma once

#include <cstddef>
#include <string>

namespace valijson {
namespace internal {

namespace detail {

/**
 * @brief  Parse a fixed number of decimal digits
 *
 * @param  s      string to parse
 * @param  pos    position of the first digit
 * @param  count  number of digits to parse
 * @param  value  set to the parsed value on success
 *
 * @return \c true if \p count digits were found at \p pos
 */
inline bool parseDateTimeDigits(const std::string &s, size_t pos, size_t count,
                                int &value)
{
    if (pos + count > s.size()) {
        return false;
    }

    value = 0;
    for (size_t i = pos; i < pos + count; ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        value = value * 10 + (s[i] - '0');
    }

    return true;
}

/**
 * @brief  Check whether a string contains a full-date, as defined in RFC 3339,
 *         section 5.6, at a given position
 *
 * A full-date has the form YYYY-MM-DD. The day must exist in the given month,
 * applying the Gregorian leap year rules.
 */
inline bool isFullDateAt(const std::string &s, size_t pos)
{
    int year = 0;
    int month = 0;
    int day = 0;
    if (!parseDateTimeDigits(s, pos, 4, year) || pos + 4 >= s.size() ||
        s[pos + 4] != '-' || !parseDateTimeDigits(s, pos + 5, 2, month) ||
        pos + 7 >= s.size() || s[pos + 7] != '-' ||
        !parseDateTimeDigits(s, pos + 8, 2, day)) {
        return false;
    }

    if (month < 1 || month > 12 || day < 1) {
        return false;
    }

    int daysInMonth = 31;
    if (month == 2) {
        const bool leap =
            (year % 4 == 0) && ((year % 100 != 0) || (year % 400 == 0));
        daysInMonth = leap ? 29 : 28;
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        daysInMonth = 30;
    }

    return day <= daysInMonth;
}

/**
 * @brief  Check whether a string contains a full-time, as defined in RFC 3339,
 *         section 5.6, from a given position to the end of the string
 *
 * A full-time has the form HH:MM:SS, with optional fractional seconds,
 * followed by a time offset of 'Z', 'z' or +HH:MM / -HH:MM. In permissive
 * mode, the time offset may be omitted.
 *
 * A leap second (SS = 60) is only permitted when the time is 23:59:60 in UTC.
 */
inline bool isFullTimeFrom(const std::string &s, size_t pos, bool strict)
{
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (!parseDateTimeDigits(s, pos, 2, hour) || pos + 2 >= s.size() ||
        s[pos + 2] != ':' || !parseDateTimeDigits(s, pos + 3, 2, minute) ||
        pos + 5 >= s.size() || s[pos + 5] != ':' ||
        !parseDateTimeDigits(s, pos + 6, 2, second)) {
        return false;
    }

    if (hour > 23 || minute > 59 || second > 60) {
        return false;
    }

    // time-secfrac = "." 1*DIGIT
    size_t i = pos + 8;
    if (i < s.size() && s[i] == '.') {
        const size_t fractionStart = ++i;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            ++i;
        }
        if (i == fractionStart) {
            return false;
        }
    }

    // time-offset = "Z" / time-numoffset
    int offsetMinutes = 0;
    if (i == s.size()) {
        if (strict) {
            return false;
        }
    } else if (s[i] == 'Z' || s[i] == 'z') {
        if (i + 1 != s.size()) {
            return false;
        }
    } else if (s[i] == '+' || s[i] == '-') {
        int offsetHour = 0;
        int offsetMinute = 0;
        if (i + 6 != s.size() ||
            !parseDateTimeDigits(s, i + 1, 2, offsetHour) || s[i + 3] != ':' ||
            !parseDateTimeDigits(s, i + 4, 2, offsetMinute) ||
            offsetHour > 23 || offsetMinute > 59) {
            return false;
        }
        offsetMinutes =
            (s[i] == '-' ? -1 : 1) * (offsetHour * 60 + offsetMinute);
    } else {
        return false;
    }

    if (second == 60) {
        // Convert the local time to UTC minutes, wrapping into [0, 1440), and
        // compare against 23:59 UTC
        int utcMinutes = hour * 60 + minute - offsetMinutes;
        utcMinutes = ((utcMinutes % 1440) + 1440) % 1440;
        return utcMinutes == 23 * 60 + 59;
    }

    return true;
}

} // namespace detail

/**
 * @brief  Check whether a string is a full-date, as defined in RFC 3339,
 *         section 5.6
 *
 * @param  s  string to check
 *
 * @return \c true if \p s is a date like 2022-07-18
 */
inline bool isDate(const std::string &s)
{
    return s.size() == 10 && detail::isFullDateAt(s, 0);
}

/**
 * @brief  Check whether a string is a full-time, as defined in RFC 3339,
 *         section 5.6
 *
 * @param  s       string to check
 * @param  strict  whether the time offset is required
 *
 * @return \c true if \p s is a time like 16:52:45Z or 16:52:45+02:00, or, in
 *         permissive mode, 16:52:45
 */
inline bool isTime(const std::string &s, bool strict)
{
    return detail::isFullTimeFrom(s, 0, strict);
}

/**
 * @brief  Check whether a string is a date-time, as defined in RFC 3339,
 *         section 5.6
 *
 * @param  s       string to check
 * @param  strict  whether the time offset is required
 *
 * @return \c true if \p s is a date-time like 2022-07-18T16:52:45Z, or, in
 *         permissive mode, 2022-07-18T16:52:45
 */
inline bool isDateTime(const std::string &s, bool strict)
{
    return s.size() > 11 && detail::isFullDateAt(s, 0) &&
           (s[10] == 'T' || s[10] == 't') &&
           detail::isFullTimeFrom(s, 11, strict);
}

} // namespace internal
} // namespace valijson

#pragma once

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <valijson/internal/regex.hpp>

namespace valijson {
namespace internal {
namespace uri {

/**
 * @brief  Check whether a URI is absolute, returns pos just past end if found
 */
inline std::optional<size_t> parseScheme(const std::string &uri)
{
    constexpr auto marker = "://";

    const auto pos = uri.find(marker);

    return pos == std::string::npos
        ? std::nullopt
        : std::make_optional<size_t>(pos + 3);
}

/**
  * @brief  Check whether a URI is absolute
  */
inline bool isUriAbsolute(const std::string &uri)
{
    return parseScheme(uri).has_value();
}

/**
 * @brief  Check whether a URI is a URN
 *
 * This function validates that the URI matches the RFC 8141 spec.
 *
 * Example: urn:isbn:978-3-16-148410-0
 */
inline bool isUrn(const std::string &documentUri) {
  static const internal::regex pattern(
      "^((urn)|(URN)):(?!urn:)([a-zA-Z0-9][a-zA-Z0-9-]{1,31})(:[-a-zA-Z0-9\\\\._~%!$&'()\\/*+,;=]+)+(\\?[-a-zA-Z0-9\\\\._~%!$&'()\\/*+,;:=]+){0,1}(#[-a-zA-Z0-9\\\\._~%!$&'()\\/*+,;:=]+){0,1}$");

  return internal::regex_match(documentUri, pattern);
}

/**
 * Resolve a relative URI reference within a given scope.
 */
inline std::string resolveRelativeUri(
        const std::string &resolutionScope,
        const std::string &relativeUri)
{
    // Trivial case: There is no relative URI to resolve
    if (relativeUri.empty()) {
        return resolutionScope;
    }

    // Trivial case: The relative URI is actually absolute, or is a URN
    if (isUriAbsolute(relativeUri) || isUrn(relativeUri)) {
        return relativeUri;
    }

    const auto schemeEnd = parseScheme(resolutionScope);
    std::string schemeAndAuthority;
    std::string basePath;
    if (schemeEnd.has_value()) {
        // Extract scheme+authority, e.g. http://userinfo@example.com:8080
        const auto authorityEnd = resolutionScope.find('/', *schemeEnd);
        schemeAndAuthority = resolutionScope.substr(0, authorityEnd);

        // Assume path starts immediately after scheme+authority
        const std::string::size_type pathStart = schemeAndAuthority.size();

        // Extract base path from resolution scope, or use '/' as default
        basePath = pathStart < resolutionScope.size()
                ? resolutionScope.substr(pathStart)
                : "/";
    } else {
        // A relative resolution scope still represents a URI path. Relative
        // references replace its final path segment rather than being appended
        // directly to the complete filename.
        basePath = resolutionScope;
    }

    // Strip everything after fragment marker if present
    const std::string::size_type baseFragmentPos = basePath.find('#');
    if (baseFragmentPos != std::string::npos) {
        basePath.erase(baseFragmentPos);
    }

    // Strip everything after query marker if present (we need both)
    const std::string::size_type baseQueryPos = basePath.find('?');
    if (baseQueryPos != std::string::npos) {
        basePath.erase(baseQueryPos);
    }

    // Next two cases...
    if (!relativeUri.empty()) {
        // Relative URI is just a fragment OR a query
        if ((relativeUri[0] == '#') || relativeUri[0] == '?') {
            // Append it to the scheme+authority and clean base path
            return schemeAndAuthority + basePath + relativeUri;
        }
    }

    // Split the relative URI into path and suffix components
    std::string relativePath = relativeUri;
    std::string suffix;
    const std::string::size_type relativeFragmentPos = relativePath.find('#');
    const std::string::size_type relativeQueryPos = relativePath.find('?');
    const std::string::size_type suffixPos =
            relativeFragmentPos == std::string::npos ? relativeQueryPos :
            relativeQueryPos == std::string::npos ? relativeFragmentPos :
            std::min(relativeFragmentPos, relativeQueryPos);
    if (suffixPos != std::string::npos) {
        suffix = relativePath.substr(suffixPos);
        relativePath.erase(suffixPos);
    }

    // Merged path can be constructed in two ways
    std::string mergedPath;
    if (!relativePath.empty() && relativePath[0] == '/') {
        // Case 1: Relative path starts with `/` so we can use it as-is
        mergedPath = relativePath;
    } else {
        // Case 2: We need to join the base path and relative path, which we do by
        // stripping the base path of any segment after its last slash
        const std::string::size_type lastSlashPos = basePath.find_last_of('/');
        mergedPath = lastSlashPos == std::string::npos
                ? relativePath
                : basePath.substr(0, lastSlashPos + 1) + relativePath;
    }

    // Resolve relative path segments
    const bool absolutePath = !mergedPath.empty() && mergedPath[0] == '/';
    std::vector<std::string> segments;
    std::string segment;
    for (const char c : mergedPath) {
        if (c == '/') {
            if (segment == "..") {
                if (!segments.empty() && segments.back() != "..") {
                    segments.pop_back();
                } else if (!absolutePath) {
                    segments.push_back(segment);
                }
            } else if (!segment.empty() && segment != ".") {
                segments.push_back(segment);
            }
            segment.clear();
        } else {
            segment += c;
        }
    }
    if (segment == "..") {
        if (!segments.empty() && segments.back() != "..") {
            segments.pop_back();
        } else if (!absolutePath) {
            segments.push_back(segment);
        }
    } else if (!segment.empty() && segment != ".") {
        segments.push_back(segment);
    }

    // Generate final normalised path
    std::string normalisedPath = absolutePath ? "/" : "";
    for (auto itr = segments.begin(); itr != segments.end(); ++itr) {
        if (itr != segments.begin()) {
            normalisedPath += "/";
        }
        normalisedPath += *itr;
    }
    if (!mergedPath.empty() && mergedPath[mergedPath.size() - 1] == '/' &&
            (normalisedPath.empty() || normalisedPath[normalisedPath.size() - 1] != '/')) {
        normalisedPath += "/";
    }

    // Construct final URI
    return schemeAndAuthority + normalisedPath + suffix;
}

} // namespace uri
} // namespace internal
} // namespace valijson

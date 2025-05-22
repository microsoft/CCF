// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"
#include "ccf/rest_verb.h"
#include "http/curl.h"
#include "http/http_builder.h"

#include <charconv>
#include <curl/curl.h>
#include <optional>
#include <span>
#include <string>
#include <vector>

#define EXPECT_HTTP_RESPONSE_STATUS(request, response, expected) \
  do \
  { \
    if (response.status_code != expected) \
    { \
      throw std::runtime_error(fmt::format( \
        "Expected {} response from {} {}, instead received {}", \
        ccf::http_status_str(expected), \
        request.method.c_str(), \
        request.url, \
        response.status_code)); \
    } \
  } while (0)

namespace snapshots
{
  // Using curl 7.68.0, so missing niceties like curl_easy_header

  using HeaderMap = std::unordered_map<std::string, std::string>;
  size_t append_header(char* buffer, size_t size, size_t nitems, void* userdata)
  {
    HeaderMap& headers = *(HeaderMap*)userdata;

    if (size != 1)
    {
      LOG_FAIL_FMT(
        "Unexpected value in curl HEADERFUNCTION callback: size = {}", size);
      return 0;
    }

    const std::string_view header =
      ccf::nonstd::trim(std::string_view(buffer, nitems));

    // Ignore HTTP status line, and empty line
    if (!header.empty() && !header.starts_with("HTTP/1.1"))
    {
      const auto [field, value] = ccf::nonstd::split_1(header, ": ");
      if (!value.empty())
      {
        headers[std::string(field)] = ccf::nonstd::trim(value);
      }
      else
      {
        LOG_INFO_FMT("Ignoring invalid-looking HTTP Header '{}'", header);
      }
    }

    return nitems * size;
  }

  using BodyHandler = std::function<void(const std::span<const uint8_t>&)>;
  size_t curl_write_callback(
    char* ptr, size_t size, size_t nmemb, void* user_data)
  {
    BodyHandler& body_handler = *(BodyHandler*)user_data;

    if (size != 1)
    {
      LOG_FAIL_FMT(
        "Unexpected value in curl WRITEFUNCTION callback: size = {}", size);
      return 0;
    }

    std::span<const uint8_t> data((const uint8_t*)ptr, size * nmemb);

    body_handler(data);

    return size * nmemb;
  }

  struct SimpleHTTPRequest
  {
    ccf::RESTVerb method;
    std::string url;
    HeaderMap headers;
    std::string ca_path;
    BodyHandler body_handler = nullptr;
  };

  struct SimpleHTTPResponse
  {
    long status_code;
    HeaderMap headers;
  };
  static inline SimpleHTTPResponse make_curl_request(
    const SimpleHTTPRequest& request)
  {
    ccf::curl::UniqueCURL curl;

    CHECK_CURL_EASY_SETOPT(curl, CURLOPT_URL, request.url.c_str());
    if (request.method == HTTP_HEAD)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_NOBODY, 1L);
    }
    else if (request.method == HTTP_GET)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_HTTPGET, 1L);
    }
    else
    {
      throw std::logic_error(
        fmt::format("Unsupported HTTP method: {}", request.method.c_str()));
    }

    SimpleHTTPResponse response;
    CHECK_CURL_EASY_SETOPT(curl, CURLOPT_HEADERDATA, &response.headers);
    CHECK_CURL_EASY_SETOPT(curl, CURLOPT_HEADERFUNCTION, append_header);

    curl_easy_setopt(curl, CURLOPT_CAINFO, request.ca_path.c_str());

    ccf::curl::UniqueSlist list;
    for (const auto& [k, v] : request.headers)
    {
      list.append(fmt::format("{}: {}", k, v).c_str());
    }

    CHECK_CURL_EASY_SETOPT(curl, CURLOPT_HTTPHEADER, list.get());

    if (request.body_handler != nullptr)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEDATA, &request.body_handler);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    }

    LOG_TRACE_FMT(
      "Sending curl request {} {}", request.method.c_str(), request.url);

    CHECK_CURL_EASY(curl_easy_perform, curl);

    CHECK_CURL_EASY_GETINFO(
      curl, CURLINFO_RESPONSE_CODE, &response.status_code);

    LOG_TRACE_FMT(
      "{} {} returned {}",
      request.method.c_str(),
      request.url,
      response.status_code);

    return response;
  }

  struct SnapshotResponse
  {
    std::string snapshot_name;
    std::vector<uint8_t> snapshot_data;
  };

  static std::optional<SnapshotResponse> fetch_from_peer(
    const std::string& peer_address,
    const std::string& path_to_peer_cert,
    size_t latest_local_snapshot)
  {
    try
    {
      // Make initial request, which returns a redirect response to specific
      // snapshot
      std::string snapshot_url;
      {
        const auto initial_url = fmt::format(
          "https://{}/node/snapshot?since={}",
          peer_address,
          latest_local_snapshot);

        SimpleHTTPRequest initial_request;
        initial_request.method = HTTP_HEAD;
        initial_request.url = initial_url;
        initial_request.ca_path = path_to_peer_cert;

        const auto initial_response = make_curl_request(initial_request);
        if (initial_response.status_code == HTTP_STATUS_NOT_FOUND)
        {
          LOG_INFO_FMT(
            "Peer has no snapshot newer than {}", latest_local_snapshot);
          return std::nullopt;
        }
        else if (initial_response.status_code != HTTP_STATUS_PERMANENT_REDIRECT)
        {
          EXPECT_HTTP_RESPONSE_STATUS(
            initial_request, initial_response, HTTP_STATUS_PERMANENT_REDIRECT);
        }

        auto location_it =
          initial_response.headers.find(ccf::http::headers::LOCATION);
        if (location_it == initial_response.headers.end())
        {
          throw std::runtime_error(fmt::format(
            "Expected {} header in redirect response from {} {}, none found",
            ccf::http::headers::LOCATION,
            initial_request.method.c_str(),
            initial_request.url));
        }

        LOG_TRACE_FMT("Snapshot fetch redirected to {}", location_it->second);

        snapshot_url =
          fmt::format("https://{}{}", peer_address, location_it->second);
      }

      // Make follow-up request to redirected URL, to fetch total content size
      size_t content_size;
      {
        SimpleHTTPRequest snapshot_size_request;
        snapshot_size_request.method = HTTP_HEAD;
        snapshot_size_request.url = snapshot_url;
        snapshot_size_request.ca_path = path_to_peer_cert;

        const auto snapshot_size_response =
          make_curl_request(snapshot_size_request);

        EXPECT_HTTP_RESPONSE_STATUS(
          snapshot_size_request, snapshot_size_response, HTTP_STATUS_OK);

        auto content_size_it = snapshot_size_response.headers.find(
          ccf::http::headers::CONTENT_LENGTH);
        if (content_size_it == snapshot_size_response.headers.end())
        {
          throw std::runtime_error(fmt::format(
            "Expected {} header in redirect response from {} {}, none found",
            ccf::http::headers::CONTENT_LENGTH,
            snapshot_size_request.method.c_str(),
            snapshot_size_request.url));
        }

        const auto& content_size_s = content_size_it->second;
        const auto [p, ec] = std::from_chars(
          content_size_s.data(),
          content_size_s.data() + content_size_s.size(),
          content_size);
        if (ec != std::errc())
        {
          throw std::runtime_error(fmt::format(
            "Invalid {} header in redirect response from {} {}: {}",
            ccf::http::headers::CONTENT_LENGTH,
            snapshot_size_request.method.c_str(),
            snapshot_size_request.url,
            ec));
        }
      }

      // Fetch 4MB chunks at a time
      constexpr size_t range_size = 4 * 1024 * 1024;
      LOG_TRACE_FMT(
        "Preparing to fetch {}-byte snapshot from peer, {} bytes per-request",
        content_size,
        range_size);

      std::vector<uint8_t> snapshot(content_size);

      {
        auto range_start = 0;
        auto range_end = std::min(content_size, range_size);

        while (true)
        {
          SimpleHTTPRequest snapshot_range_request;
          snapshot_range_request.method = HTTP_GET;
          snapshot_range_request.url = snapshot_url;
          snapshot_range_request.headers["range"] =
            fmt::format("bytes={}-{}", range_start, range_end);
          snapshot_range_request.ca_path = path_to_peer_cert;

          snapshot_range_request.body_handler = [&](const auto& data) {
            LOG_TRACE_FMT(
              "Copying {} bytes into snapshot, starting at {}",
              range_size,
              range_start);
            memcpy(snapshot.data() + range_start, data.data(), data.size());
            range_start += data.size();
          };

          const auto range_response = make_curl_request(snapshot_range_request);

          EXPECT_HTTP_RESPONSE_STATUS(
            snapshot_range_request,
            range_response,
            HTTP_STATUS_PARTIAL_CONTENT);

          if (range_end == content_size)
          {
            break;
          }

          range_start = range_end;
          range_end = std::min(content_size, range_start + range_size);
        }
      }

      const auto url_components = ccf::nonstd::split(snapshot_url, "/");
      const std::string snapshot_name(url_components.back());

      return SnapshotResponse{snapshot_name, std::move(snapshot)};
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Error during snapshot fetch: {}", e.what());
      return std::nullopt;
    }
  }
}
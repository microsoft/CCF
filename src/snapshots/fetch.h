// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"
#include "ccf/rest_verb.h"
#include "http/http_builder.h"

#include <charconv>
#include <curl/curl.h>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

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

    // Ignore HTTP status line
    if (!header.starts_with("HTTP/1.1"))
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
    CURL* curl;

    curl = curl_easy_init();
    if (!curl)
    {
      throw std::runtime_error("Error initialising curl easy request");
    }

    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    if (request.method == HTTP_HEAD)
    {
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    }
    else if (request.method == HTTP_GET)
    {
      curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }
    else
    {
      throw std::logic_error(
        fmt::format("Unsupported HTTP method: {}", request.method.c_str()));
    }

    SimpleHTTPResponse response;
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response.headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, append_header);

    // TODO: Should have a cert for them, right?
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    struct curl_slist* list = nullptr;
    for (const auto& [k, v] : request.headers)
    {
      list = curl_slist_append(list, fmt::format("{}: {}", k, v).c_str());
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

    if (request.body_handler != nullptr)
    {
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &request.body_handler);
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    }

    LOG_INFO_FMT(
      "!!! Sending curl request {} {}", request.method.c_str(), request.url);

    auto res = curl_easy_perform(curl);

    // TODO: Handle errors
    LOG_INFO_FMT("!!! Curl perform result is {}", res);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status_code);

    curl_slist_free_all(list);
    curl_easy_cleanup(curl);

    return response;
  }

  struct SnapshotResponse
  {
    std::string snapshot_name;
    std::vector<uint8_t> snapshot_data;
  };

  static std::optional<SnapshotResponse> fetch_from_peer(
    const std::string& peer_address, size_t latest_local_snapshot)
  {
    const auto initial_url = fmt::format(
      "https://{}/node/snapshot?since={}", peer_address, latest_local_snapshot);

    SimpleHTTPRequest initial_request;
    initial_request.method = HTTP_HEAD;
    initial_request.url = initial_url;
    const auto initial_response = make_curl_request(initial_request);
    if (initial_response.status_code == HTTP_STATUS_NOT_FOUND)
    {
      LOG_INFO_FMT("Peer has no snapshot newer than {}", latest_local_snapshot);
      return std::nullopt;
    }
    else if (initial_response.status_code != HTTP_STATUS_PERMANENT_REDIRECT)
    {
      LOG_FAIL_FMT("TODO: Expected permanent redirect response");
    }

    auto location_it = initial_response.headers.find("location");
    if (location_it == initial_response.headers.end())
    {
      LOG_FAIL_FMT("TODO: Missing Location header");
    }

    LOG_INFO_FMT("!!! Redirected to {}", location_it->second);

    const auto snapshot_url =
      fmt::format("https://{}{}", peer_address, location_it->second);

    SimpleHTTPRequest snapshot_size_request;
    snapshot_size_request.method = HTTP_HEAD;
    snapshot_size_request.url = snapshot_url;
    const auto snapshot_size_response =
      make_curl_request(snapshot_size_request);
    if (snapshot_size_response.status_code != HTTP_STATUS_OK)
    {
      LOG_FAIL_FMT("TODO: Expected OK response");
    }

    auto content_size_it =
      snapshot_size_response.headers.find(ccf::http::headers::CONTENT_LENGTH);
    if (content_size_it == snapshot_size_response.headers.end())
    {
      LOG_FAIL_FMT("TODO: Missing content-size header");
    }

    LOG_INFO_FMT(
      "!!! Parsing content size header: {}", content_size_it->second);
    size_t content_size;
    const auto& content_size_s = content_size_it->second;
    const auto [p, ec] = std::from_chars(
      content_size_s.data(),
      content_size_s.data() + content_size_s.size(),
      content_size);
    if (ec != std::errc())
    {
      LOG_FAIL_FMT("TODO: Invalid content size!?");
    }

    LOG_INFO_FMT("!!! Content size is {}", content_size);

    std::vector<uint8_t> snapshot(content_size);
    {
      // TODO: Decide sensible chunk size, 4MB?
      constexpr size_t range_size = 4 * 1024;

      auto range_start = 0;
      auto range_end = std::min(content_size, range_size);

      while (true)
      {
        // TODO: Copy response body back
        SimpleHTTPRequest snapshot_range_request;
        snapshot_range_request.method = HTTP_GET;
        snapshot_range_request.url = snapshot_url;
        snapshot_range_request.headers["range"] =
          fmt::format("bytes={}-{}", range_start, range_end);

        snapshot_range_request.body_handler = [&](const auto& data) {
          const auto range_size = range_end - range_start;
          if (data.size() != range_size)
          {
            LOG_FAIL_FMT(
              "Asked for a range from {} to {} ({} bytes). Received a response "
              "of {} bytes",
              range_start,
              range_end,
              range_size,
              data.size());
          }

          LOG_INFO_FMT(
            "!!! Copying {} bytes into snapshot, starting at {}",
            range_size,
            range_start);
          memcpy(snapshot.data() + range_start, data.data(), data.size());
        };

        const auto range_response = make_curl_request(snapshot_range_request);

        if (range_response.status_code != HTTP_STATUS_PARTIAL_CONTENT)
        {
          LOG_FAIL_FMT(
            "Got error HTTP response: {}", range_response.status_code);
        }

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
}
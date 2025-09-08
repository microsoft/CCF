// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/rest_verb.h"
#include "ds/internal_logger.h.h"
#include "http/curl.h"
#include "http/http_builder.h"

#include <charconv>
#include <curl/curl.h>
#include <llhttp/llhttp.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#define EXPECT_HTTP_RESPONSE_STATUS(request, status_code, expected) \
  do \
  { \
    if (status_code != expected) \
    { \
      throw std::runtime_error(fmt::format( \
        "Expected {} response from {} {}, instead received {}", \
        ccf::http_status_str(expected), \
        request.get_method().c_str(), \
        request.get_url(), \
        status_code)); \
    } \
  } while (0)

namespace snapshots
{
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
        ccf::curl::UniqueCURL curl_easy;
        curl_easy.set_opt(CURLOPT_CAINFO, path_to_peer_cert.c_str());

        auto initial_url = fmt::format(
          "https://{}/node/snapshot?since={}",
          peer_address,
          latest_local_snapshot);

        ccf::curl::UniqueSlist headers;

        auto request = ccf::curl::CurlRequest(
          std::move(curl_easy),
          HTTP_HEAD,
          std::move(initial_url),
          std::move(headers),
          nullptr, // No request body
          nullptr, // No response body
          std::nullopt // No response callback
        );

        long status_code = 0;
        CURLcode curl_response = CURLE_OK;
        request.synchronous_perform(curl_response, status_code);
        if (curl_response != CURLE_OK)
        {
          throw std::runtime_error(fmt::format(
            "Error fetching snapshot redirect from {}: {} ({})",
            request.get_url(),
            curl_easy_strerror(curl_response),
            status_code));
        }
        if (status_code == HTTP_STATUS_NOT_FOUND)
        {
          LOG_INFO_FMT(
            "Peer has no snapshot newer than {}", latest_local_snapshot);
          return std::nullopt;
        }
        EXPECT_HTTP_RESPONSE_STATUS(
          request, status_code, HTTP_STATUS_PERMANENT_REDIRECT);

        auto& response_headers = request.get_response_headers();
        auto location_it =
          response_headers.data.find(ccf::http::headers::LOCATION);
        if (location_it == response_headers.data.end())
        {
          throw std::runtime_error(fmt::format(
            "Expected {} header in redirect response from {} {}, none found",
            ccf::http::headers::LOCATION,
            request.get_method().c_str(),
            request.get_url()));
        }

        LOG_TRACE_FMT("Snapshot fetch redirected to {}", location_it->second);

        snapshot_url =
          fmt::format("https://{}{}", peer_address, location_it->second);
      }

      // Make follow-up request to redirected URL, to fetch total content size
      size_t content_size = 0;
      {
        ccf::curl::UniqueCURL curl_easy;
        curl_easy.set_opt(CURLOPT_CAINFO, path_to_peer_cert.c_str());

        ccf::curl::UniqueSlist headers;

        std::string current_snapshot_url = snapshot_url;

        ccf::curl::CurlRequest snapshot_size_request(
          std::move(curl_easy),
          HTTP_HEAD,
          std::move(current_snapshot_url),
          std::move(headers),
          nullptr, // No request body
          nullptr, // No response body
          std::nullopt // No response callback
        );

        CURLcode snapshot_size_curl_code = CURLE_OK;
        long snapshot_size_status_code = 0;
        snapshot_size_request.synchronous_perform(
          snapshot_size_curl_code, snapshot_size_status_code);

        if (snapshot_size_curl_code != CURLE_OK)
        {
          throw std::runtime_error(fmt::format(
            "Error fetching snapshot size from {}: {} ({})",
            snapshot_size_request.get_url(),
            curl_easy_strerror(snapshot_size_curl_code),
            snapshot_size_status_code));
        }

        EXPECT_HTTP_RESPONSE_STATUS(
          snapshot_size_request, snapshot_size_status_code, HTTP_STATUS_OK);

        auto& snapshot_size_response_headers =
          snapshot_size_request.get_response_headers();

        auto content_size_it = snapshot_size_response_headers.data.find(
          ccf::http::headers::CONTENT_LENGTH);

        if (content_size_it == snapshot_size_response_headers.data.end())
        {
          throw std::runtime_error(fmt::format(
            "Expected {} header in response from {} {}, none found",
            ccf::http::headers::CONTENT_LENGTH,
            snapshot_size_request.get_method().c_str(),
            snapshot_size_request.get_url()));
        }

        const auto& content_size_s = content_size_it->second;
        const auto [p, ec] = std::from_chars(
          content_size_s.data(),
          content_size_s.data() + content_size_s.size(),
          content_size);
        if (ec != std::errc())
        {
          throw std::runtime_error(fmt::format(
            "Failed to parse {} header in response from {} {}: {}",
            ccf::http::headers::CONTENT_LENGTH,
            snapshot_size_request.get_method().c_str(),
            snapshot_size_request.get_url(),
            ec));
        }
      }

      // Fetch 4MB chunks at a time
      constexpr size_t range_size = 4L * 1024 * 1024;
      LOG_TRACE_FMT(
        "Preparing to fetch {}-byte snapshot from peer, {} bytes per-request",
        content_size,
        range_size);

      auto snapshot_response =
        std::make_unique<ccf::curl::ResponseBody>(content_size);

      {
        auto range_start = 0;
        auto range_end = std::min(content_size, range_size);

        while (true)
        {
          ccf::curl::UniqueCURL curl_easy;
          curl_easy.set_opt(CURLOPT_CAINFO, path_to_peer_cert.c_str());

          ccf::curl::UniqueSlist headers;
          headers.append(
            "Range", fmt::format("bytes={}-{}", range_start, range_end));

          std::string current_snapshot_url = snapshot_url;

          ccf::curl::CurlRequest snapshot_range_request(
            std::move(curl_easy),
            HTTP_GET,
            std::move(current_snapshot_url),
            std::move(headers),
            nullptr, // No request body
            std::move(snapshot_response),
            std::nullopt // No response callback
          );

          CURLcode curl_response = CURLE_OK;
          long snapshot_range_status_code = 0;
          snapshot_range_request.synchronous_perform(
            curl_response, snapshot_range_status_code);
          if (curl_response != CURLE_OK)
          {
            throw std::runtime_error(fmt::format(
              "Error fetching snapshot chunk range from {}: {} ({})",
              snapshot_range_request.get_url(),
              curl_easy_strerror(curl_response),
              snapshot_range_status_code));
          }
          EXPECT_HTTP_RESPONSE_STATUS(
            snapshot_range_request,
            snapshot_range_status_code,
            HTTP_STATUS_PARTIAL_CONTENT);

          LOG_TRACE_FMT(
            "Received {}-byte chunk from {}: {} bytes",
            range_end - range_start,
            snapshot_range_request.get_url(),
            snapshot_range_status_code);

          snapshot_response =
            std::move(snapshot_range_request.get_response_ptr());

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

      return SnapshotResponse{
        snapshot_name, std::move(snapshot_response->buffer)};
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Error during snapshot fetch: {}", e.what());
      return std::nullopt;
    }
  }
}
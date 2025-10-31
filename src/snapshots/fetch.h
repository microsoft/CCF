// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/nonstd.h"
#include "ccf/rest_verb.h"
#include "ds/internal_logger.h"
#include "http/curl.h"
#include "http/http_builder.h"

#include <charconv>
#include <curl/curl.h>
#include <llhttp/llhttp.h>
#include <memory>
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
        request->get_method().c_str(), \
        request->get_url(), \
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

  struct ContentRangeHeader
  {
    size_t range_start;
    size_t range_end;
    size_t total_size;
  };

  static ContentRangeHeader parse_content_range_header(
    const ccf::curl::CurlRequest& request)
  {
    const auto& headers = request.get_response_headers();

    auto it = headers.find(ccf::http::headers::CONTENT_RANGE);
    if (it == headers.end())
    {
      throw std::runtime_error(
        "Response is missing expected content-range header");
    }

    auto [unit, remaining] = ccf::nonstd::split_1(it->second, " ");
    if (unit != "bytes")
    {
      throw std::runtime_error(
        "Unexpected content-range unit. Only 'bytes' is supported");
    }

    auto [range, total_size] = ccf::nonstd::split_1(remaining, "/");
    auto [range_start, range_end] = ccf::nonstd::split_1(range, "-");

    if (range_start.empty() || range_end.empty() || total_size.empty())
    {
      throw std::runtime_error(fmt::format(
        "Unsupported content-range header format. Expected 'bytes "
        "<begin>-<end>/<total>', received: {}",
        it->second));
    }

    ContentRangeHeader parsed_values;

    {
      const auto [p, ec] = std::from_chars(
        range_start.begin(), range_start.end(), parsed_values.range_start);
      if (ec != std::errc())
      {
        throw std::runtime_error(fmt::format(
          "Could not parse range start ({}) from content-range header: {}",
          range_start,
          it->second));
      }
    }

    {
      const auto [p, ec] = std::from_chars(
        range_end.begin(), range_end.end(), parsed_values.range_end);
      if (ec != std::errc())
      {
        throw std::runtime_error(fmt::format(
          "Could not parse range end ({}) from content-range header: {}",
          range_end,
          it->second));
      }
    }

    {
      const auto [p, ec] = std::from_chars(
        total_size.begin(), total_size.end(), parsed_values.total_size);
      if (ec != std::errc())
      {
        throw std::runtime_error(fmt::format(
          "Could not parse total size ({}) from content-range header: {}",
          total_size,
          it->second));
      }
    }

    return parsed_values;
  }

  static std::optional<SnapshotResponse> try_fetch_from_peer(
    const std::string& peer_address,
    const std::string& path_to_peer_ca,
    size_t max_size)
  {
    try
    {
      ccf::curl::UniqueCURL curl_easy;
      curl_easy.set_opt(CURLOPT_CAINFO, path_to_peer_ca.c_str());

      auto response_body = std::make_unique<ccf::curl::ResponseBody>(max_size);

      // Get snapshot. This may be redirected multiple times, and we follow
      // these redirects ourself so we can extract the final URL. Once the
      // redirects terminate, the final response is likely to be extremely large
      // so is fetched over multiple requests for a sub-range, returning
      // PARTIAL_CONTENT each time.
      std::string snapshot_url =
        fmt::format("https://{}/node/snapshot", peer_address);

      // Fetch 4MB chunks at a time
      constexpr size_t range_size = 4L * 1024 * 1024;
      size_t range_start = 0;
      size_t range_end = range_size;
      bool fetched_all = false;

      auto process_partial_response =
        [&](const ccf::curl::CurlRequest& request) {
          auto content_range = parse_content_range_header(request);

          if (content_range.range_start != range_start)
          {
            throw std::runtime_error(fmt::format(
              "Unexpected range response. Requested bytes {}-{}, received "
              "range starting at {}",
              range_start,
              range_end,
              content_range.range_start));
          }

          // The server may give us _less_ than we requested (since they know
          // where the file ends), but should never give us more
          if (content_range.range_end > range_end)
          {
            throw std::runtime_error(fmt::format(
              "Unexpected range response. Requested bytes {}-{}, received "
              "range ending at {}",
              range_start,
              range_end,
              content_range.range_end));
          }

          const auto range_size =
            content_range.range_end - content_range.range_start;
          LOG_TRACE_FMT(
            "Received {}-byte chunk from {}. Now have {}/{}",
            range_size,
            request.get_url(),
            content_range.range_end,
            content_range.total_size);

          if (content_range.range_end == content_range.total_size)
          {
            fetched_all = true;
          }
          else
          {
            // Advance range for next request
            range_start = range_end;
            range_end = range_start + range_size;
          }
        };

      const auto max_redirects = 20;
      for (auto redirect_count = 1; redirect_count <= max_redirects;
           ++redirect_count)
      {
        LOG_DEBUG_FMT(
          "Making snapshot discovery request {}/{} to {}",
          redirect_count,
          max_redirects,
          snapshot_url);

        ccf::curl::UniqueSlist headers;
        headers.append(
          "Range", fmt::format("bytes={}-{}", range_start, range_end));

        CURLcode curl_response = CURLE_FAILED_INIT;
        long status_code = 0;
        std::unique_ptr<ccf::curl::CurlRequest> request;
        ccf::curl::CurlRequest::ResponseCallback response_callback =
          [&curl_response, &status_code, &request](
            std::unique_ptr<ccf::curl::CurlRequest>&& request_,
            CURLcode curl_response_,
            long status_code_) {
            curl_response = curl_response_;
            status_code = status_code_;
            request = std::move(request_);
          };

        ccf::curl::CurlRequest::synchronous_perform(
          std::make_unique<ccf::curl::CurlRequest>(
            std::move(curl_easy),
            HTTP_GET,
            snapshot_url,
            std::move(headers),
            nullptr, // No request body
            std::move(response_body),
            std::move(response_callback)));

        if (curl_response != CURLE_OK)
        {
          throw std::runtime_error(fmt::format(
            "Error fetching snapshot redirect from {}: {} ({})",
            request->get_url(),
            curl_easy_strerror(curl_response),
            status_code));
        }

        if (status_code == HTTP_STATUS_NOT_FOUND)
        {
          LOG_INFO_FMT("Peer has no suitable snapshot");
          return std::nullopt;
        }

        if (status_code == HTTP_STATUS_PARTIAL_CONTENT)
        {
          process_partial_response(*request);

          response_body = std::move(request->get_response_ptr());
          curl_easy = std::move(request->get_easy_handle_ptr());
          break;
        }

        EXPECT_HTTP_RESPONSE_STATUS(
          request, status_code, HTTP_STATUS_PERMANENT_REDIRECT);

        char* redirect_url = nullptr;
        CHECK_CURL_EASY_GETINFO(
          request->get_easy_handle(), CURLINFO_REDIRECT_URL, &redirect_url);
        if (redirect_url == nullptr)
        {
          throw std::runtime_error(
            "Redirect response found, but CURLINFO_REDIRECT_URL returned no "
            "value");
        }

        LOG_DEBUG_FMT(
          "Snapshot fetch received redirect response with location {}",
          redirect_url);
        snapshot_url = redirect_url;

        response_body = std::move(request->get_response_ptr());
        curl_easy = std::move(request->get_easy_handle_ptr());

        // Ignore any body from redirect responses
        response_body->buffer.clear();
      }

      while (!fetched_all)
      {
        ccf::curl::UniqueSlist headers;
        headers.append(
          "Range", fmt::format("bytes={}-{}", range_start, range_end));

        std::unique_ptr<ccf::curl::CurlRequest> snapshot_range_request;
        CURLcode curl_response = CURLE_OK;
        long snapshot_range_status_code = 0;

        ccf::curl::CurlRequest::ResponseCallback snapshot_response_callback =
          [&](
            std::unique_ptr<ccf::curl::CurlRequest>&& request_,
            CURLcode curl_response_,
            long status_code_) {
            snapshot_range_request = std::move(request_);
            curl_response = curl_response_;
            snapshot_range_status_code = status_code_;
          };

        ccf::curl::CurlRequest::synchronous_perform(
          std::make_unique<ccf::curl::CurlRequest>(
            std::move(curl_easy),
            HTTP_GET,
            snapshot_url,
            std::move(headers),
            nullptr, // No request body
            std::move(response_body),
            snapshot_response_callback));
        if (curl_response != CURLE_OK)
        {
          throw std::runtime_error(fmt::format(
            "Error fetching snapshot chunk range from {}: {} ({})",
            snapshot_range_request->get_url(),
            curl_easy_strerror(curl_response),
            snapshot_range_status_code));
        }
        EXPECT_HTTP_RESPONSE_STATUS(
          snapshot_range_request,
          snapshot_range_status_code,
          HTTP_STATUS_PARTIAL_CONTENT);

        process_partial_response(*snapshot_range_request);

        response_body = std::move(snapshot_range_request->get_response_ptr());
        curl_easy = std::move(snapshot_range_request->get_easy_handle_ptr());
      }

      const auto url_components = ccf::nonstd::split(snapshot_url, "/");
      const std::string snapshot_name(url_components.back());

      return SnapshotResponse{snapshot_name, std::move(response_body->buffer)};
    }
    catch (const std::exception& e)
    {
      LOG_FAIL_FMT("Error during snapshot fetch: {}", e.what());
      return std::nullopt;
    }
  }

  static std::optional<SnapshotResponse> fetch_from_peer(
    const std::string& peer_address,
    const std::string& path_to_peer_ca,
    size_t max_attempts,
    size_t retry_delay_ms,
    size_t max_size)
  {
    for (size_t attempt = 0; attempt < max_attempts; ++attempt)
    {
      LOG_INFO_FMT(
        "Fetching snapshot from {} (attempt {}/{})",
        peer_address,
        attempt + 1,
        max_attempts);

      if (attempt > 0)
      {
        std::this_thread::sleep_for(std::chrono::milliseconds(retry_delay_ms));
      }

      auto response =
        try_fetch_from_peer(peer_address, path_to_peer_ca, max_size);
      if (response.has_value())
      {
        return response;
      }
    }
    LOG_INFO_FMT(
      "Exceeded maximum snapshot fetch retries ({}), giving up", max_attempts);
    return std::nullopt;
  }
}
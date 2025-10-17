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

  static std::optional<SnapshotResponse> try_fetch_from_peer(
    const std::string& peer_address,
    const std::string& path_to_peer_ca,
    size_t latest_local_snapshot)
  {
    try
    {
      ccf::curl::UniqueCURL curl_easy;
      curl_easy.set_opt(CURLOPT_CAINFO, path_to_peer_ca.c_str());

      // Make initial requests, following redirects to a specific snapshot,
      // resulting in final path and snapshot size
      std::string snapshot_url = fmt::format(
        "https://{}/node/snapshot?since={}",
        peer_address,
        latest_local_snapshot);
      size_t content_size = 0;

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
            HTTP_HEAD,
            snapshot_url,
            std::move(headers),
            nullptr, // No request body
            nullptr, // No response body
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
          LOG_INFO_FMT(
            "Peer has no snapshot newer than {}", latest_local_snapshot);
          return std::nullopt;
        }

        if (status_code == HTTP_STATUS_OK)
        {
          // This first non-redirect response should include a content size
          // header telling us the size of the snapshot
          auto& response_headers = request->get_response_headers();

          auto content_size_it =
            response_headers.data.find(ccf::http::headers::CONTENT_LENGTH);

          if (content_size_it == response_headers.data.end())
          {
            throw std::runtime_error(fmt::format(
              "Expected {} header in response from {} {}, none found",
              ccf::http::headers::CONTENT_LENGTH,
              request->get_method().c_str(),
              request->get_url()));
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
              request->get_method().c_str(),
              request->get_url(),
              ec));
          }

          LOG_INFO_FMT(
            "Snapshot discovery completed after {}/{} redirects. Fetching "
            "snapshot of size {} from {}",
            redirect_count,
            max_redirects,
            content_size,
            snapshot_url);
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

        curl_easy = std::move(request->get_easy_handle_ptr());
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
          ccf::curl::UniqueSlist headers;
          headers.append(
            "Range", fmt::format("bytes={}-{}", range_start, range_end));

          std::string current_snapshot_url = snapshot_url;

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
              std::move(current_snapshot_url),
              std::move(headers),
              nullptr, // No request body
              std::move(snapshot_response),
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

          LOG_TRACE_FMT(
            "Received {}-byte chunk from {}: {} bytes",
            range_end - range_start,
            snapshot_range_request->get_url(),
            snapshot_range_status_code);

          snapshot_response =
            std::move(snapshot_range_request->get_response_ptr());
          curl_easy = std::move(snapshot_range_request->get_easy_handle_ptr());

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

  static std::optional<SnapshotResponse> fetch_from_peer(
    const std::string& peer_address,
    const std::string& path_to_peer_ca,
    size_t latest_local_snapshot,
    size_t max_attempts,
    size_t retry_delay_ms)
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

      auto response = try_fetch_from_peer(
        peer_address, path_to_peer_ca, latest_local_snapshot);
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
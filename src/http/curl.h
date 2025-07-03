// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"

#include <curl/curl.h>
#include <memory>
#include <span>

#define CHECK_CURL_EASY(fn, ...) \
  do \
  { \
    const auto res = fn(__VA_ARGS__); \
    if (res != CURLE_OK) \
    { \
      throw std::runtime_error(fmt::format( \
        "Error calling " #fn ": {} ({})", res, curl_easy_strerror(res))); \
    } \
  } while (0)

#define CHECK_CURL_EASY_SETOPT(handle, info, arg) \
  CHECK_CURL_EASY(curl_easy_setopt, handle, info, arg)
#define CHECK_CURL_EASY_GETINFO(handle, info, arg) \
  CHECK_CURL_EASY(curl_easy_getinfo, handle, info, arg)

#define CHECK_CURL_MULTI(fn, ...) \
  do \
  { \
    const auto res = fn(__VA_ARGS__); \
    if (res != CURLM_OK) \
    { \
      throw std::runtime_error(fmt::format( \
        "Error calling " #fn ": {} ({})", res, curl_multi_strerror(res))); \
    } \
  } while (0)

namespace ccf::curl
{

  class UniqueCURL
  {
  protected:
    std::unique_ptr<CURL, void (*)(CURL*)> p;

  public:
    UniqueCURL() : p(curl_easy_init(), [](auto x) { curl_easy_cleanup(x); })
    {
      if (!p.get())
      {
        throw std::runtime_error("Error initialising curl easy request");
      }
    }

    operator CURL*() const
    {
      return p.get();
    }
  };

  class UniqueCURLM
  {
  protected:
    std::unique_ptr<CURLM, void (*)(CURLM*)> p;

  public:
    UniqueCURLM() : p(curl_multi_init(), [](auto x) { curl_multi_cleanup(x); })
    {
      if (!p.get())
      {
        throw std::runtime_error("Error initialising curl multi request");
      }
    }

    operator CURLM*() const
    {
      return p.get();
    }
  };

  class UniqueSlist
  {
  protected:
    std::unique_ptr<curl_slist, void (*)(curl_slist*)> p;

  public:
    UniqueSlist() : p(nullptr, [](auto x) { curl_slist_free_all(x); }) {}

    void append(const char* str)
    {
      p.reset(curl_slist_append(p.release(), str));
    }

    curl_slist* get() const
    {
      return p.get();
    }
  };

  class RequestBody
  {
    std::vector<uint8_t> buffer_vec;
    std::span<const uint8_t> buffer_span;

  public:
    RequestBody(std::vector<uint8_t>& buffer) : buffer_vec(std::move(buffer))
    {
      buffer_span =
        std::span<const uint8_t>(buffer_vec.data(), buffer_vec.size());
    }

    template <typename Jsonable>
    RequestBody(Jsonable jsonable)
    {
      auto json_str = nlohmann::json(jsonable).dump();
      buffer_vec = std::vector<uint8_t>(
        json_str.begin(), json_str.end()); // Convert to vector of bytes
      buffer_span =
        std::span<const uint8_t>(buffer_vec.data(), buffer_vec.size());
    }

    static size_t send_data(
      char* ptr, size_t size, size_t nitems, void* userdata)
    {
      auto* data = static_cast<RequestBody*>(userdata);
      auto bytes_to_copy = std::min(data->buffer_span.size(), size * nitems);
      memcpy(ptr, data->buffer_span.data(), bytes_to_copy);
      data->buffer_span = data->buffer_span.subspan(bytes_to_copy);
      return bytes_to_copy;
    }

    void attach_to_curl(CURL* curl)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_READDATA, this);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_READFUNCTION, send_data);
      CHECK_CURL_EASY_SETOPT(
        curl, CURLOPT_INFILESIZE, static_cast<curl_off_t>(buffer_span.size()));
    }
  };

  class ResponseBody
  {
  public:
    std::vector<uint8_t> buffer;

    static size_t write_response_chunk(
      char* ptr, size_t size, size_t nmemb, void* userdata)
    {
      auto* data = static_cast<ResponseBody*>(userdata);
      auto bytes_to_copy = size * nmemb;
      data->buffer.insert(
        data->buffer.end(), (uint8_t*)ptr, (uint8_t*)ptr + bytes_to_copy);
      // Should probably set a maximum response size here
      return bytes_to_copy;
    }

    void attach_to_curl(CURL* curl)
    {
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEDATA, this);
      // Called one or more times to add more data
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEFUNCTION, write_response_chunk);
    }
  };

  class CurlRequest
  {
  public:
    UniqueCURL curl_handle;
    std::string url;
    std::unique_ptr<ccf::curl::RequestBody> request_body = nullptr;
    std::unique_ptr<ccf::curl::ResponseBody> response_body = nullptr;
    ccf::curl::UniqueSlist headers;
    std::optional<std::function<void(const ResponseBody&)>> response_callback =
      std::nullopt;

    void attach_to_curl() const
    {
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_URL, url.c_str());
      if (request_body != nullptr)
      {
        request_body->attach_to_curl(curl_handle);
        CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_UPLOAD, 1L);
      }
      if (response_body != nullptr)
      {
        response_body->attach_to_curl(curl_handle);
      }
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_HTTPHEADER, headers.get());
    }

    void set_url(const std::string& new_url)
    {
      url = new_url;
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_URL, url.c_str());
    }

    void set_blob_opt(auto option, const uint8_t* data, size_t length)
    {
      struct curl_blob blob
      {
        .data = const_cast<uint8_t*>(data), .len = length,
        .flags = CURL_BLOB_COPY,
      };

      CHECK_CURL_EASY_SETOPT(curl_handle, option, blob);
    }

    void set_response_callback(
      std::function<void(const ResponseBody&)> callback)
    {
      if (response_body != nullptr || response_callback.has_value())
      {
        throw std::logic_error(
          "Only one response callback can be set for a request.");
      }
      response_callback = std::move(callback);
      response_body = std::make_unique<ResponseBody>();
    }

    static void attach_to_multi_curl(
      CURLM* curl_multi, std::unique_ptr<CurlRequest>& request)
    {
      request->attach_to_curl();
      CURL* curl_handle = request->curl_handle;
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_PRIVATE, request.release());
      CHECK_CURL_MULTI(curl_multi_add_handle, curl_multi, curl_handle);
    }
  };

  inline int iter_CURLM_CurlRequest(UniqueCURLM& p)
  {
    int running_handles = 0;
    CHECK_CURL_MULTI(curl_multi_perform, p, &running_handles);

    // handle all completed curl requests
    int msgq = 0;
    CURLMsg* msg = nullptr;
    do
    {
      msg = curl_multi_info_read(p, &msgq);

      if ((msg != nullptr) && msg->msg == CURLMSG_DONE)
      {
        auto* easy = msg->easy_handle;
        auto result = msg->data.result;

        LOG_INFO_FMT(
          "CURL request response handling with result: {} ({})",
          result,
          curl_easy_strerror(result));

        // retrieve the request data and attach a lifetime to it
        ccf::curl::CurlRequest* request_data = nullptr;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &request_data);
        std::unique_ptr<ccf::curl::CurlRequest> request_data_ptr(request_data);

        // Clean up the easy handle and corresponding resources
        curl_multi_remove_handle(p, easy);
        if (request_data->response_callback.has_value())
        {
          if (request_data->response_body != nullptr)
          {
            request_data->response_callback.value()(
              *request_data->response_body);
          }
        }
        // Handled by the destructor of CurlRequest
        LOG_INFO_FMT(
          "Finished handling CURLMSG: msg_nullptr: {}, remaining: {}",
          msg != nullptr,
          msgq);
      }
    } while (msgq > 0);
    return running_handles;
  }
} // namespace ccf::curl
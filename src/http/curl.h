// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"

#include <cstdint>
#include <curl/curl.h>
#include <curl/multi.h>
#include <memory>
#include <span>
#include <stdexcept>
#include <uv.h>

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
  private:
    std::unique_ptr<CURL, void (*)(CURL*)> p;

  public:
    UniqueCURL() : p(curl_easy_init(), [](auto x) { curl_easy_cleanup(x); })
    {
      if (!p)
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
  private:
    std::unique_ptr<CURLM, void (*)(CURLM*)> p;

  public:
    UniqueCURLM() : p(curl_multi_init(), [](auto x) { curl_multi_cleanup(x); })
    {
      if (!p)
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
  private:
    std::unique_ptr<curl_slist, void (*)(curl_slist*)> p;

  public:
    UniqueSlist() : p(nullptr, [](auto x) { curl_slist_free_all(x); }) {}

    void append(const char* str)
    {
      p.reset(curl_slist_append(p.release(), str));
    }

    [[nodiscard]] curl_slist* get() const
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
      uint8_t* ptr, size_t size, size_t nmemb, void* userdata)
    {
      auto* data = static_cast<ResponseBody*>(userdata);
      auto bytes_to_copy = size * nmemb;
      data->buffer.insert(data->buffer.end(), ptr, ptr + bytes_to_copy);
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

  // Use in conjunction with the iter_CURLM_CurlRequest function
  // to force only requests with the corresponding CurlRequest private data
  class CurlRequestCURLM
  {
  private:
    CURLM* curl_multi;

  public:
    CurlRequestCURLM(CURLM* curl_multi) : curl_multi(curl_multi)
    {
      if (curl_multi == nullptr)
      {
        throw std::runtime_error("CURLM handle cannot be null");
      }
    }

    [[nodiscard]] CURLM* get() const
    {
      return curl_multi;
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
      const CurlRequestCURLM& curl_multi, std::unique_ptr<CurlRequest>& request)
    {
      request->attach_to_curl();
      CURL* curl_handle = request->curl_handle;
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_PRIVATE, request.release());
      CHECK_CURL_MULTI(curl_multi_add_handle, curl_multi.get(), curl_handle);
    }
  };

  inline int iter_CURLM_CurlRequest(const CurlRequestCURLM& p)
  {
    int running_handles = 0;
    CHECK_CURL_MULTI(curl_multi_perform, p.get(), &running_handles);

    // handle all completed curl requests
    int msgq = 0;
    CURLMsg* msg = nullptr;
    do
    {
      msg = curl_multi_info_read(p.get(), &msgq);

      if ((msg != nullptr) && msg->msg == CURLMSG_DONE)
      {
        auto* easy = msg->easy_handle;
        auto result = msg->data.result;

        LOG_TRACE_FMT(
          "CURL request response handling with result: {} ({})",
          result,
          curl_easy_strerror(result));

        // retrieve the request data and attach a lifetime to it
        ccf::curl::CurlRequest* request_data = nullptr;
        curl_easy_getinfo(easy, CURLINFO_PRIVATE, &request_data);
        if (request_data == nullptr)
        {
          throw std::runtime_error(
            "CURLMSG_DONE received with no associated request data");
        }
        std::unique_ptr<ccf::curl::CurlRequest> request_data_ptr(request_data);

        // Clean up the easy handle and corresponding resources
        curl_multi_remove_handle(p.get(), easy);
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

  class CurlmLibuvContext
  {
    uv_loop_t* loop;
    uv_timer_t timeout_tracker{};
    // lifetime handler of curl_multi interface
    UniqueCURLM curl_multi;
    // utility class to enforce type safety on accesses to curl_multi
    CurlRequestCURLM curl_request_curlm;

    struct RequestContext
    {
      uv_poll_t poll_handle;
      curl_socket_t socket;
      CurlmLibuvContext* context;
    };

  public:
    void handle_request_messages()
    {
      iter_CURLM_CurlRequest(curl_request_curlm);
    }

    static void libuv_timeout_callback(uv_timer_t* handle)
    {
      auto* self = static_cast<CurlmLibuvContext*>(handle->data);
      if (self == nullptr)
      {
        throw std::logic_error(
          "libuv_timeout_callback called with null self pointer");
      }

      int running_handles = 0;
      CHECK_CURL_MULTI(
        curl_multi_socket_action,
        self->curl_multi,
        CURL_SOCKET_TIMEOUT,
        0,
        &running_handles);
      self->handle_request_messages();
    }

    static int curl_timeout_callback(
      CURLM* multi, long timeout_ms, CurlmLibuvContext* self)
    {
      (void)multi;
      if (self == nullptr)
      {
        throw std::logic_error(
          "libuv_timeout_callback called with null self pointer");
      }

      if (timeout_ms < 0)
      {
        // No timeout set, stop the timer
        uv_timer_stop(&self->timeout_tracker);
      }
      else
      {
        // If timeout is zero, this will trigger on the next uv loop iteration
        uv_timer_start(&self->timeout_tracker, libuv_timeout_callback, 0, 0);
      }
      return 0;
    }

    // Called when libuv detects a socket event
    static void libuv_socket_poll_callback(
      uv_poll_t* req, int status, int events)
    {
      if (status < 0)
      {
        LOG_FAIL_FMT("Socket poll error: {}", uv_strerror(status));
        return;
      }

      auto* request_context = static_cast<RequestContext*>(req->data);
      if (request_context == nullptr)
      {
        throw std::logic_error(
          "libuv_socket_poll_callback called with null request context");
      }

      auto* self = request_context->context;
      if (self == nullptr)
      {
        throw std::logic_error(
          "libuv_socket_poll_callback called with null self pointer");
      }

      int action = 0;
      action |= ((events & UV_READABLE) != 0) ? CURL_CSELECT_IN : 0;
      action |= ((events & UV_WRITABLE) != 0) ? CURL_CSELECT_OUT : 0;
      int running_handles = 0;
      CHECK_CURL_MULTI(
        curl_multi_socket_action,
        self->curl_multi,
        request_context->socket,
        action,
        &running_handles);
      self->handle_request_messages();
    }

    // Called when the status of a socket changes (creation/deletion)
    static int curl_socket_callback(
      CURL* easy,
      curl_socket_t s,
      int action,
      CurlmLibuvContext* self,
      RequestContext* request_context)
    {
      (void)easy;
      switch (action)
      {
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
        {
          if (request_context == nullptr)
          {
            auto request_context_ptr = std::make_unique<RequestContext>();
            request_context_ptr->context = self;
            request_context_ptr->socket = s;
            uv_poll_init_socket(
              self->loop, &request_context_ptr->poll_handle, s);
            request_context_ptr->poll_handle.data =
              request_context_ptr.get(); // Attach the context
            // attach the lifetime to the socket handle
            request_context = request_context_ptr.release();
            CHECK_CURL_MULTI(
              curl_multi_assign, self->curl_multi, s, request_context);
          }

          int events = 0;
          events |= (action == CURL_POLL_IN) ? 0 : UV_WRITABLE;
          events |= (action == CURL_POLL_OUT) ? 0 : UV_READABLE;
          uv_poll_start(
            &request_context->poll_handle, events, libuv_socket_poll_callback);
          break;
        }
        case CURL_POLL_REMOVE:
          if (request_context != nullptr)
          {
            uv_poll_stop(&request_context->poll_handle);
            std::unique_ptr<RequestContext> request_context_ptr(
              request_context);
            curl_multi_assign(self->curl_multi, s, nullptr);
          }
          break;
        default:
          throw std::runtime_error("Unknown action in curl_socket_callback");
      }
      return 0;
    }

    CurlmLibuvContext(uv_loop_t* loop) :
      loop(loop),
      curl_request_curlm(curl_multi)
    {
      uv_timer_init(loop, &timeout_tracker);
      timeout_tracker.data = this; // Attach this instance to the timer

      // attach timeouts
      CHECK_CURL_MULTI(curl_multi_setopt, curl_multi, CURLMOPT_TIMERDATA, this);
      CHECK_CURL_MULTI(
        curl_multi_setopt,
        curl_multi,
        CURLMOPT_TIMERFUNCTION,
        curl_timeout_callback);

      // attach socket events
      CHECK_CURL_MULTI(
        curl_multi_setopt, curl_multi, CURLMOPT_SOCKETDATA, this);
      CHECK_CURL_MULTI(
        curl_multi_setopt,
        curl_multi,
        CURLMOPT_SOCKETFUNCTION,
        curl_socket_callback);
    }

    // should this return a reference or a pointer?
    [[nodiscard]] const CurlRequestCURLM& curlm() const
    {
      return curl_request_curlm;
    }
  };

  class CurlmLibuvContextSingleton
  {
    static CurlmLibuvContext* curlm_libuv_context_instance;
  public:
    static CurlmLibuvContext*& get_instance_unsafe()
    {
      return curlm_libuv_context_instance;
    }
    static CurlmLibuvContext& get_instance()
    {
      if (curlm_libuv_context_instance == nullptr)
      {
        throw std::logic_error(
          "CurlmLibuvContextSingleton instance not initialized");
      }
      return *curlm_libuv_context_instance;
    }
  };

  inline CurlmLibuvContext* CurlmLibuvContextSingleton::curlm_libuv_context_instance =
    nullptr;
} // namespace ccf::curl
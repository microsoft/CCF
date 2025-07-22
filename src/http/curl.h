// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"

#include <cstdint>
#include <curl/curl.h>
#include <curl/multi.h>
#include <memory>
#include <regex>
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
    std::vector<uint8_t> buffer;
    std::span<const uint8_t> unsent;

  public:
    RequestBody(std::vector<uint8_t>& buffer) : buffer(buffer)
    {
      unsent = std::span<const uint8_t>(buffer.data(), buffer.size());
    }

    RequestBody(std::vector<uint8_t>&& buffer) : buffer(std::move(buffer))
    {
      unsent = std::span<const uint8_t>(buffer.data(), buffer.size());
    }

    RequestBody(nlohmann::json json)
    {
      auto json_str = json.dump();
      buffer = std::vector<uint8_t>(
        json_str.begin(), json_str.end()); // Convert to vector of bytes
      unsent = std::span<const uint8_t>(buffer.data(), buffer.size());
    }

    static size_t send_data(
      char* ptr, size_t size, size_t nitems, RequestBody* data)
    {
      if (data == nullptr)
      {
        LOG_FAIL_FMT("send_data called with null userdata");
        return 0;
      }
      auto bytes_to_copy = std::min(data->unsent.size(), size * nitems);
      memcpy(ptr, data->unsent.data(), bytes_to_copy);
      data->unsent = data->unsent.subspan(bytes_to_copy);
      return bytes_to_copy;
    }

    void attach_to_curl(CURL* curl)
    {
      if (curl == nullptr)
      {
        throw std::logic_error(
          "Cannot attach request body to a null CURL handle");
      }
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_READDATA, this);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_READFUNCTION, send_data);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_INFILESIZE, unsent.size());
    }
  };

  class Response
  {
  public:
    std::vector<uint8_t> buffer;
    using HeaderMap = std::unordered_map<std::string, std::string>;
    HeaderMap headers;
    long status_code = 0;

    static size_t write_response_chunk(
      uint8_t* ptr, size_t size, size_t nmemb, Response* response)
    {
      if (response == nullptr)
      {
        LOG_FAIL_FMT(
          "write_response_chunk called with a null response pointer");
        return 0;
      }
      auto bytes_to_copy = size * nmemb;
      response->buffer.insert(response->buffer.end(), ptr, ptr + bytes_to_copy);
      // Should probably set a maximum response size here
      return bytes_to_copy;
    }

    static size_t recv_header_line(
      char* buffer, size_t size, size_t nitems, Response* response)
    {
      if (response == nullptr)
      {
        LOG_FAIL_FMT("recv_header_line called with a null response pointer");
        return 0;
      }
      auto bytes_to_read = size * nitems;
      std::string_view header(buffer, bytes_to_read);

      // strip /r/n etc
      header = ccf::nonstd::trim(header);

      // Ignore empty headers, and the http response line (e.g. "HTTP/1.1 200")
      static const std::regex http_status_line_regex(R"(^HTTP\/[1-9]+.*)");
      if (
        !header.empty() &&
        !std::regex_match(std::string(header), http_status_line_regex))
      {
        const auto [field, value] = ccf::nonstd::split_1(header, ": ");
        if (!value.empty())
        {
          std::string field_str(field);
          nonstd::to_lower(field_str);
          response->headers[field_str] = ccf::nonstd::trim(value);
        }
        else
        {
          LOG_INFO_FMT("Ignoring invalid-looking HTTP Header '{}'", header);
        }
      }

      return bytes_to_read;
    }

    void attach_to_curl(CURL* curl)
    {
      if (curl == nullptr)
      {
        throw std::logic_error("Cannot attach response to a null CURL handle");
      }
      // Body
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEDATA, this);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_WRITEFUNCTION, write_response_chunk);
      // Headers
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_HEADERDATA, this);
      CHECK_CURL_EASY_SETOPT(curl, CURLOPT_HEADERFUNCTION, recv_header_line);
    }
  };

  class CurlRequest
  {
  public:
    UniqueCURL curl_handle;
    std::string url;
    std::unique_ptr<ccf::curl::RequestBody> request_body = nullptr;
    std::unique_ptr<ccf::curl::Response> response = nullptr;
    ccf::curl::UniqueSlist headers;
    std::optional<std::function<void(CurlRequest&)>> response_callback =
      std::nullopt;

    void attach_to_curl() const
    {
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_URL, url.c_str());
      if (request_body != nullptr)
      {
        request_body->attach_to_curl(curl_handle);
        CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_UPLOAD, 1L);
      }
      if (response != nullptr)
      {
        response->attach_to_curl(curl_handle);
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

    void set_response_callback(std::function<void(CurlRequest&)> callback)
    {
      if (response != nullptr || response_callback.has_value())
      {
        throw std::logic_error(
          "Only one response callback can be set for a request.");
      }
      response_callback = std::move(callback);
      response = std::make_unique<Response>();
    }

    void set_header(const std::string& key, const std::string& value)
    {
      headers.append(fmt::format("{}: {}", key, value).c_str());
    }

    [[nodiscard]] CURL* get_easy_handle() const
    {
      return curl_handle;
    }
  };

  // non-owning wrapper around a CURLM handle which supports CurlRequest
  class CurlRequestCURLM
  {
  private:
    CURLM* curl_multi;

    CurlRequestCURLM(CURLM* curl_multi) : curl_multi(curl_multi)
    {
      if (curl_multi == nullptr)
      {
        throw std::runtime_error("CURLM handle cannot be null");
      }
    }

  public:
    [[nodiscard]] CURLM* get() const
    {
      return curl_multi;
    }

    void attach_curl_request(std::unique_ptr<CurlRequest>& request)
    {
      if (request == nullptr)
      {
        throw std::logic_error("Cannot attach a null CurlRequest");
      }
      request->attach_to_curl();
      CURL* curl_handle = request->curl_handle;
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_PRIVATE, request.release());
      CHECK_CURL_MULTI(curl_multi_add_handle, curl_multi, curl_handle);
    }

    static CurlRequestCURLM create_unsafe(CURLM* curl_multi)
    {
      if (curl_multi == nullptr)
      {
        throw std::runtime_error("CURLM handle cannot be null");
      }
      return {curl_multi};
    }

    int perform_unsafe()
    {
      int running_handles = 0;
      CHECK_CURL_MULTI(curl_multi_perform, curl_multi, &running_handles);

      // handle all completed curl requests
      int msgq = 0;
      CURLMsg* msg = nullptr;
      do
      {
        msg = curl_multi_info_read(curl_multi, &msgq);

        if ((msg != nullptr) && msg->msg == CURLMSG_DONE)
        {
          auto* easy = msg->easy_handle;
          auto result = msg->data.result;

          LOG_TRACE_FMT(
            "CURL request response handling with result: {} ({})",
            result,
            curl_easy_strerror(result));

          // retrieve the request data and attach a lifetime to it
          ccf::curl::CurlRequest* request = nullptr;
          curl_easy_getinfo(easy, CURLINFO_PRIVATE, &request);
          if (request == nullptr)
          {
            throw std::runtime_error(
              "CURLMSG_DONE received with no associated request data");
          }
          std::unique_ptr<ccf::curl::CurlRequest> request_data_ptr(request);

          if (request->response != nullptr)
          {
            CHECK_CURL_EASY_GETINFO(
              easy, CURLINFO_RESPONSE_CODE, &request->response->status_code);
          }

          // Clean up the easy handle and corresponding resources
          curl_multi_remove_handle(curl_multi, easy);
          if (request->response_callback.has_value())
          {
            if (request->response != nullptr)
            {
              request->response_callback.value()(*request);
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
  };

  class CurlmLibuvContext
  {
    /* Very high level:
     * CURLM triggers timeout callback with some delay for libuv
     * libuv calls the timeout callback which then triggers the curl socket
     *   action
     * curl calls the socket callback to register the libuv polling
     * libuv waits on the socket events and calls the socket poll callback
     * socket poll callback triggers relevant libuv action
     * etc.
     *
     * Example flow:
     *
     * Initially a CURL* is attached to the curl_multi CURLM* handle
     * This calls the curl_multi's timeout function curl_timeout_callback with 0
     *   delay
     * which then registers the libuv timeout callback with 0 delay
     * libuv_timeout_callback then registers a timeout socket_action with curl
     * which then registers the socket polling at the libuv level
     *
     * At this point, either the relevant timeout will fire and call the
     * relevant timeout callbacks, or the socket polling will trigger allowing
     * data to be sent/received
     */
  private:
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
      curl_request_curlm.perform_unsafe();
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
        // If timeout is zero, this will trigger immediately
        timeout_ms = std::max(timeout_ms, 1L);
        uv_timer_start(
          &self->timeout_tracker, libuv_timeout_callback, timeout_ms, 0);
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
      curl_request_curlm(CurlRequestCURLM::create_unsafe(curl_multi))
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

      LOG_INFO_FMT("Created CURLM libuv context");

      // kickstart timeout, probably a no-op but allows curl to initialise
      int running_handles = 0;
      CHECK_CURL_MULTI(
        curl_multi_socket_action,
        curl_multi,
        CURL_SOCKET_TIMEOUT,
        0,
        &running_handles);

      LOG_INFO_FMT("Kickstarted CURLM libuv context");
    }

    // should this return a reference or a pointer?
    [[nodiscard]] CurlRequestCURLM& curlm()
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

  inline CurlmLibuvContext*
    CurlmLibuvContextSingleton::curlm_libuv_context_instance = nullptr;
} // namespace ccf::curl
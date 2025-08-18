// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "ccf/ds/nonstd.h"
#include "ccf/rest_verb.h"

#include <cstdint>
#include <curl/curl.h>
#include <curl/multi.h>
#include <memory>
#include <mutex>
#include <optional>
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

    void set_blob_opt(auto option, const uint8_t* data, size_t length)
    {
      if (data == nullptr || length == 0)
      {
        throw std::invalid_argument(
          "Data pointer cannot be null or length zero");
      }

      if (p == nullptr)
      {
        throw std::logic_error("Cannot set option on a null CURL handle");
      }

      struct curl_blob blob
      {
        .data = const_cast<uint8_t*>(data), .len = length,
        .flags = CURL_BLOB_COPY,
      };

      CHECK_CURL_EASY_SETOPT(p.get(), option, &blob);
    }

    void set_opt(auto option, auto value)
    {
      CHECK_CURL_EASY_SETOPT(p.get(), option, value);
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

    CURLM* release()
    {
      if (!p)
      {
        return p.release();
      }
      return nullptr;
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
    ~UniqueSlist() = default;
    UniqueSlist(const UniqueSlist&) = delete;
    UniqueSlist& operator=(const UniqueSlist&) = delete;
    UniqueSlist(UniqueSlist&& other) noexcept : p(std::move(other.p)) {}
    UniqueSlist& operator=(UniqueSlist&& other) noexcept
    {
      p = std::move(other.p);
      return *this;
    }

    void append(const char* str)
    {
      p.reset(curl_slist_append(p.release(), str));
    }

    void append(const std::string& key, const std::string& value)
    {
      append(fmt::format("{}: {}", key, value).c_str());
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
          if (response->headers.contains(field_str))
          {
            auto current = response->headers[field_str];
            LOG_FAIL_FMT(
              "Duplicate header for '{}', current = '{}', new = '{}'",
              field_str,
              current,
              value);
          }
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
    using ResponseCallback = std::function<void(
      CurlRequest& request, CURLcode curl_response_code, long status_code)>;

  private:
    UniqueCURL curl_handle;
    RESTVerb method = HTTP_GET;
    std::string url;
    ccf::curl::UniqueSlist headers;
    std::unique_ptr<ccf::curl::RequestBody> request_body = nullptr;
    ccf::curl::Response response;
    std::optional<ResponseCallback> response_callback = std::nullopt;

  public:
    CurlRequest(
      UniqueCURL&& curl_handle_,
      RESTVerb method_,
      std::string&& url_,
      UniqueSlist&& headers_,
      std::unique_ptr<RequestBody>&& request_body_,
      std::optional<ResponseCallback>&& response_callback_) :
      curl_handle(std::move(curl_handle_)),
      method(method_),
      url(std::move(url_)),
      headers(std::move(headers_)),
      request_body(std::move(request_body_)),
      response_callback(std::move(response_callback_))
    {
      if (url.empty())
      {
        throw std::invalid_argument("URL cannot be empty");
      }
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_URL, url.c_str());

      if (!method.get_http_method().has_value())
      {
        throw std::logic_error(
          fmt::format("Unsupported HTTP method: {}", method.c_str()));
      }
      switch (method.get_http_method().value())
      {
        case HTTP_GET:
          CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_HTTPGET, 1L);
          break;
        case HTTP_HEAD:
          CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_NOBODY, 1L);
          break;
        case HTTP_PUT:
        {
          CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_UPLOAD, 1L);
          if (request_body == nullptr)
          {
            // If no request body is provided, curl will try reading from stdin,
            // which causes a blockage
            request_body =
              std::make_unique<RequestBody>(std::vector<uint8_t>());
          }
        }
        break;
        case HTTP_POST:
          // libcurl sets the post verb when CURLOPT_POSTFIELDS is set, so we
          // skip doing so here, and we assume that the user has already set
          // these fields
          break;
        default:
          throw std::logic_error(
            fmt::format("Unsupported HTTP method: {}", method.c_str()));
      }

      if (request_body != nullptr)
      {
        request_body->attach_to_curl(curl_handle);
      }

      response.attach_to_curl(curl_handle);

      if (headers.get() != nullptr)
      {
        CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_HTTPHEADER, headers.get());
      }
    }

    void handle_response(CURLcode curl_response_code)
    {
      if (response_callback.has_value())
      {
        long status_code = 0;
        CHECK_CURL_EASY_GETINFO(
          curl_handle, CURLINFO_RESPONSE_CODE, &status_code);
        response_callback.value()(*this, curl_response_code, status_code);
      }
    }

    void synchronous_perform(CURLcode& curl_code, long& status_code)
    {
      if (curl_handle == nullptr)
      {
        throw std::logic_error(
          "Cannot curl_easy_perform on a null CURL handle");
      }

      curl_code = curl_easy_perform(curl_handle);

      handle_response(curl_code); // handle the response callback if set

      CHECK_CURL_EASY_GETINFO(
        curl_handle, CURLINFO_RESPONSE_CODE, &status_code);
    }

    [[nodiscard]] CURL* get_easy_handle() const
    {
      return curl_handle;
    }

    [[nodiscard]] RESTVerb get_method() const
    {
      return method;
    }

    [[nodiscard]] std::string get_url() const
    {
      return url;
    }

    [[nodiscard]] ccf::curl::Response& get_response()
    {
      return response;
    }
  };

  // non-owning wrapper around a CURLM handle which supports CurlRequest
  class CurlRequestCURLM
  {
  private:
    UniqueCURLM curl_multi;

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
      CURL* curl_handle = request->get_easy_handle();
      CHECK_CURL_EASY_SETOPT(curl_handle, CURLOPT_PRIVATE, request.release());
      CHECK_CURL_MULTI(curl_multi_add_handle, curl_multi, curl_handle);
    }

    int perform()
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

          // retrieve the request data and attach a lifetime to it
          ccf::curl::CurlRequest* request = nullptr;
          curl_easy_getinfo(easy, CURLINFO_PRIVATE, &request);
          if (request == nullptr)
          {
            throw std::runtime_error(
              "CURLMSG_DONE received with no associated request data");
          }
          std::unique_ptr<ccf::curl::CurlRequest> request_data_ptr(request);

          // detach the easy handle such that it can be cleaned up with the
          // destructor of CurlRequest
          curl_multi_remove_handle(curl_multi, easy);
          request->handle_response(result);
        }
      } while (msgq > 0);
      return running_handles;
    }

    CURLM* release()
    {
      return curl_multi.release();
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
    // utility class to enforce type safety on accesses to curl_multi wrapping a
    // UniqueCURLM
    CurlRequestCURLM curl_request_curlm;

    // We need a lock to prevent a client thread calling curl_multi_add_handle
    // while the libuv thread is processing a curl callback
    //
    // Note that since the a client callback can call curl_multi_add_handle, but
    // that will be difficult/impossible to detect, we need curlm_lock to be
    // recursive.
    std::recursive_mutex curlm_lock;

    struct RequestContext
    {
      uv_poll_t poll_handle;
      curl_socket_t socket;
      CurlmLibuvContext* context;
    };

  public:
    // Stop all curl transfers and remove handles from libuv
    void stop()
    {
      std::lock_guard<std::recursive_mutex> lock(curlm_lock);
      LOG_INFO_FMT("Stopping curl transfers and removing handles from libuv");
      if (curl_request_curlm.get() == nullptr)
      {
        throw std::logic_error(
          "Cannot stop curl transfers on a null CURLM handle");
      }
      // Stop all curl easy handles
      {
        CURL** easy_handles = curl_multi_get_handles(curl_request_curlm.get());
        for (int i = 0; easy_handles[i] != nullptr; ++i)
        {
          auto* easy = easy_handles[i];
          curl_multi_remove_handle(curl_request_curlm.get(), easy);
          if (easy != nullptr)
          {
            // attach a lifetime to the request
            ccf::curl::CurlRequest* request = nullptr;
            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &request);
            if (request == nullptr)
            {
              LOG_FAIL_FMT(
                "CURLMSG_DONE received with no associated request data");
            }
            std::unique_ptr<ccf::curl::CurlRequest> request_data_ptr(request);
            curl_multi_remove_handle(curl_request_curlm.get(), easy);
            curl_easy_cleanup(easy);
          }
        }
        curl_free(easy_handles);
        auto* curlm = curl_request_curlm.release();
        if (curlm != nullptr)
        {
          // calls socket callbacks to remove the handles from libuv
          LOG_INFO_FMT("Cleaning up CURLM handle");
          curl_multi_cleanup(curlm);
        }
      }

      // There should be no more sockets from curl in libuv, so we can stop the
      // timeout
      uv_close(reinterpret_cast<uv_handle_t*>(&timeout_tracker), nullptr);
    }

    void handle_request_messages()
    {
      curl_request_curlm.perform();
    }

    static void libuv_timeout_callback(uv_timer_t* handle)
    {
      auto* self = static_cast<CurlmLibuvContext*>(handle->data);
      if (self == nullptr)
      {
        throw std::logic_error(
          "libuv_timeout_callback called with null self pointer");
      }
      std::lock_guard<std::recursive_mutex> lock(self->curlm_lock);

      if (self->curl_request_curlm.get() == nullptr)
      {
        LOG_FAIL_FMT("libuv_timeout_callback called with null CURLM handle");
        return;
      }

      int running_handles = 0;
      CHECK_CURL_MULTI(
        curl_multi_socket_action,
        self->curl_request_curlm.get(),
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
      std::lock_guard<std::recursive_mutex> lock(self->curlm_lock);

      if (self->curl_request_curlm.get() == nullptr)
      {
        LOG_FAIL_FMT(
          "libuv_socket_poll_callback called with null CURLM handle");
        return;
      }

      int action = 0;
      action |= ((events & UV_READABLE) != 0) ? CURL_CSELECT_IN : 0;
      action |= ((events & UV_WRITABLE) != 0) ? CURL_CSELECT_OUT : 0;
      int running_handles = 0;
      CHECK_CURL_MULTI(
        curl_multi_socket_action,
        self->curl_request_curlm.get(),
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
      if (self == nullptr)
      {
        throw std::logic_error(
          "curl_socket_callback called with null self pointer");
      }
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
              curl_multi_assign,
              self->curl_request_curlm.get(),
              s,
              request_context);
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
            curl_multi_assign(self->curl_request_curlm.get(), s, nullptr);
          }
          break;
        default:
          throw std::runtime_error("Unknown action in curl_socket_callback");
      }
      return 0;
    }

    CurlmLibuvContext(uv_loop_t* loop) : loop(loop)
    {
      uv_timer_init(loop, &timeout_tracker);
      timeout_tracker.data = this; // Attach this instance to the timer

      // attach timeouts
      CHECK_CURL_MULTI(
        curl_multi_setopt, curl_request_curlm.get(), CURLMOPT_TIMERDATA, this);
      CHECK_CURL_MULTI(
        curl_multi_setopt,
        curl_request_curlm.get(),
        CURLMOPT_TIMERFUNCTION,
        curl_timeout_callback);

      // attach socket events
      CHECK_CURL_MULTI(
        curl_multi_setopt, curl_request_curlm.get(), CURLMOPT_SOCKETDATA, this);
      CHECK_CURL_MULTI(
        curl_multi_setopt,
        curl_request_curlm.get(),
        CURLMOPT_SOCKETFUNCTION,
        curl_socket_callback);

      // kickstart timeout, probably a no-op but allows curl to initialise
      int running_handles = 0;
      CHECK_CURL_MULTI(
        curl_multi_socket_action,
        curl_request_curlm.get(),
        CURL_SOCKET_TIMEOUT,
        0,
        &running_handles);
    }

    void attach_request(std::unique_ptr<CurlRequest>& request)
    {
      std::lock_guard<std::recursive_mutex> lock(curlm_lock);
      curl_request_curlm.attach_curl_request(request);
    }
  };

  class CurlmLibuvContextSingleton
  {
  public:
    static CurlmLibuvContext*& get_instance_unsafe()
    {
      static CurlmLibuvContext* curlm_libuv_context_instance = nullptr;
      return curlm_libuv_context_instance;
    }
    static CurlmLibuvContext& get_instance()
    {
      auto*& instance = get_instance_unsafe();
      if (instance == nullptr)
      {
        throw std::logic_error(
          "CurlmLibuvContextSingleton instance not initialized");
      }
      return *instance;
    }
  };
} // namespace ccf::curl
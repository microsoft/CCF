// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/http_client.h"

#include <chrono>
#include <cstring>
#include <curl/curl.h>
#include <curl/easy.h>
#include <curl/multi.h>
#include <curl/urlapi.h>
#include <new>
#include <ratio>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  static bool initialized = false;

  static size_t body_write_fun(
    char* ptr, size_t size, size_t nmemb, void* userdata)
  {
    HTTPResponse* r = static_cast<HTTPResponse*>(userdata);
    size_t real_size = nmemb * size;
    r->body += std::string(ptr, real_size);
    return real_size;
  }

  static size_t header_write_fun(
    char* buffer, size_t size, size_t nitems, void* userdata)
  {
    HTTPResponse* r = static_cast<HTTPResponse*>(userdata);
    size_t real_size = nitems * size;
    std::string h = std::string(buffer, real_size);
    char* colon = std::strchr(buffer, ':');
    if (colon != NULL)
    {
      std::string key(buffer, colon - buffer);
      std::string value(colon + 2, real_size - (colon - buffer) - 1);
      r->headers.emplace(std::make_pair(key, value));
    }
    return real_size;
  }

  static CURL* easy_setup(
    CURL* curl,
    const std::string& url,
    const std::string& body,
    HTTPResponse& r,
    size_t timeout,
    bool verbose)
  {
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, body_write_fun);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &r);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_write_fun);

    if (timeout != 0)
    {
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
      curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    }

    if (verbose)
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (!body.empty())
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());

    return curl;
  }

  static bool must_retry(CURL* curl, HTTPResponse& response, bool verbose)
  {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

    if (response.status == 429)
    {
      long retry_after = 0;
      curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
      if (verbose)
        printf("HTTP 429; RETRY after %lds\n", retry_after);
      std::this_thread::sleep_for(std::chrono::seconds(retry_after));
      response.body = "";
      response.headers.clear();
      response.status = 0;
      return true;
    }
    else
      return false;
  }

  HTTPResponse HTTPRequest::execute(size_t timeout, bool verbose)
  {
    if (!initialized)
    {
      curl_global_init(CURL_GLOBAL_ALL);
      atexit(curl_global_cleanup);
      initialized = true;
    }

    CURL* curl = curl_easy_init();

    if (!curl)
      throw std::runtime_error("libcurl initialization failed");

    HTTPResponse response;

    // printf("Sync: %s\n", url.c_str());

    while (max_attempts > 0)
    {
      easy_setup(curl, url, body, response, timeout, verbose);

      CURLcode curl_code = curl_easy_perform(curl);

      if (curl_code != CURLE_OK)
      {
        curl_easy_cleanup(curl);
        throw std::runtime_error(fmt::format("curl error: {}", curl_code));
      }
      else
      {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.status);

        if (must_retry(curl, response, verbose))
          max_attempts--;
        else
        {
          curl_easy_cleanup(curl);
          return response;
        }
      }
    }

    if (curl)
      curl_easy_cleanup(curl);

    throw std::runtime_error("maxmimum number of URL request retries exceeded");
  }

  class CurlClient : public HTTPClient
  {
  public:
    CurlClient(size_t request_timeout, bool verbose) :
      HTTPClient(request_timeout, verbose)
    {}

    class MonitorThread
    {
    public:
      MonitorThread(
        CurlClient* client,
        HTTPRequestSetId id,
        CURLM* multi,
        std::function<void(HTTPResponses&&)> callback) :
        keep_going(true),
        client(client),
        id(id),
        multi(multi),
        callback(callback)
      {
        t = std::thread(&MonitorThread::run, this);
        t.detach();
      }

      virtual ~MonitorThread() {}

      void stop()
      {
        keep_going = false;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }

      void run()
      {
        while (keep_going)
          keep_going &= client->poll(id, multi, callback);
      }

    protected:
      bool keep_going = true;
      std::thread t;

      CurlClient* client;
      HTTPRequestSetId id;
      CURLM* multi;
      std::function<void(HTTPResponses&&)> callback;
    };

    bool poll(
      HTTPRequestSetId id,
      CURLM* multi,
      std::function<void(HTTPResponses&&)>& callback)
    {
      auto consume_msgs = [this, id, multi]() {
        struct CURLMsg* m;
        do
        {
          int msgq = 0;
          m = curl_multi_info_read(multi, &msgq);
          if (m && m->msg == CURLMSG_DONE)
          {
            size_t i = 0;
            auto cc = curl_easy_getinfo(m->easy_handle, CURLINFO_PRIVATE, &i);
            if (cc == CURLE_OK)
              complete(id, i, m->easy_handle);
          }
        } while (m);
      };

      if (!is_complete(id))
      {
        std::lock_guard<std::mutex> guard(mtx);
        int num_active_fds = 0;
        CURLMcode mc = curl_multi_poll(multi, NULL, 0, 100, &num_active_fds);
        if (mc != CURLM_OK)
          throw std::runtime_error("curl_multi_poll failed");
        consume_msgs();
        return true;
      }
      else if (callback)
      {
        std::lock_guard<std::mutex> guard(mtx);
        consume_msgs();
        auto rsps_it = responses.find(id);
        if (rsps_it == responses.end())
          throw std::runtime_error("could not find url responses");
        HTTPResponses rs;
        rs.swap(rsps_it->second);
        callback(std::move(rs));
        responses.erase(rsps_it);
        requests.erase(id);
      }

      curl_multi_cleanup(multi);

      return false;
    }

    HTTPRequestSetId submit(
      HTTPRequests&& rs, std::function<void(HTTPResponses&&)>&& callback)
    {
      std::lock_guard<std::mutex> guard(mtx);

      if (!initialized)
      {
        curl_global_init(CURL_GLOBAL_ALL);
        atexit(curl_global_cleanup);
        initialized = true;
      }

      HTTPRequestSetId id = requests.size();
      auto [it, ok] = requests.emplace(id, TrackedRequests{std::move(rs)});
      if (!ok)
        throw std::bad_alloc();

      TrackedRequests& reqs = it->second;

      CURLM* multi = curl_multi_init();

      if (!multi)
        throw std::bad_alloc();

      reqs.multi = multi;

      auto [rsps_it, rsps_ok] =
        responses.emplace(id, HTTPResponses(reqs.requests.size()));
      if (!rsps_ok)
        throw std::bad_alloc();

      std::vector<CURL*> easies;

      for (size_t i = 0; i < reqs.requests.size(); i++)
      {
        auto& request = reqs.requests.at(i);
        // printf("Submit   %zu: %s\n", i, request.url.c_str());
        CURL* easy = curl_easy_init();
        if (!easy)
          throw std::bad_alloc();
        HTTPResponse& response = rsps_it->second[i];
        easy_setup(
          easy, request.url, request.body, response, request_timeout, verbose);
        curl_easy_setopt(easy, CURLOPT_PRIVATE, i);
        curl_multi_add_handle(multi, easy);
        easies.push_back(easy);
      }

      int running_handles = 0;
      CURLMcode curl_code = curl_multi_perform(multi, &running_handles);

      if (curl_code != CURLM_OK)
      {
        for (const auto& easy : easies)
        {
          curl_multi_remove_handle(multi, easy);
          curl_easy_cleanup(easy);
        }
        curl_multi_cleanup(multi);
        throw std::runtime_error("curl_multi_perform unsuccessful");
      }

      monitor_threads[id] =
        std::make_shared<MonitorThread>(this, id, multi, callback);

      return id;
    }

    void complete(size_t id, size_t i, CURL* easy)
    {
      // Lock held by the monitor thread

      auto rqit = requests.find(id);
      if (rqit == requests.end())
        return;

      auto multi = rqit->second.multi;

      auto rsit = responses.find(id);
      if (rsit == responses.end())
        throw std::runtime_error("response set not found");

      if (rsit->second.size() != rqit->second.requests.size())
        rsit->second.resize(rqit->second.requests.size());

      if (i >= rsit->second.size())
        throw std::runtime_error("request index too large");

      HTTPResponse& response = rsit->second.at(i);

      curl_multi_remove_handle(multi, easy);
      if (must_retry(easy, response, true))
        curl_multi_add_handle(multi, easy);
      else
      {
        curl_easy_cleanup(easy);
        // printf(
        //   "Complete %zu: %u size %zu (req. %zu)\n",
        //   i,
        //   response.status,
        //   response.body.size(),
        //   id);
      }
    }

    bool is_complete(const HTTPRequestSetId& id) const
    {
      Requests::const_iterator rit = requests.end();
      CURLMcode mc = CURLM_OK;
      int still_running = 0;
      CURLM* multi = NULL;

      {
        std::lock_guard<std::mutex> guard(mtx);
        rit = requests.find(id);
        if (rit == requests.end())
          throw std::runtime_error("no such request set");

        multi = rit->second.multi;
        mc = curl_multi_perform(multi, &still_running);
        return mc != CURLM_OK || still_running == 0;
      }
    }

  protected:
    mutable std::mutex mtx;

    struct TrackedRequests
    {
      HTTPRequests requests = {};
      CURLM* multi = NULL;
      std::function<void(HTTPResponses&&)> callback = nullptr;
      size_t timeout = 0;
    };

    typedef std::unordered_map<HTTPRequestSetId, std::shared_ptr<MonitorThread>>
      MonitorThreads;

    MonitorThreads monitor_threads;

    typedef std::unordered_map<HTTPRequestSetId, TrackedRequests> Requests;
    Requests requests;

    std::unordered_map<HTTPRequestSetId, HTTPResponses> responses;
  };

  AsynchronousHTTPClient::AsynchronousHTTPClient(
    size_t request_timeout, bool verbose)
  {
    implementation = new CurlClient(request_timeout, verbose);
  }

  AsynchronousHTTPClient::~AsynchronousHTTPClient()
  {
    delete static_cast<CurlClient*>(implementation);
  }

  HTTPRequestSetId AsynchronousHTTPClient::submit(
    HTTPRequests&& rs, std::function<void(HTTPResponses&&)>&& callback)
  {
    return static_cast<CurlClient*>(implementation)
      ->submit(std::move(rs), std::move(callback));
  }

  bool AsynchronousHTTPClient::is_complete(const HTTPRequestSetId& id) const
  {
    return static_cast<CurlClient*>(implementation)->is_complete(id);
  }
}

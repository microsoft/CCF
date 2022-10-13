// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "util.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ravl
{
  typedef size_t HTTPRequestSetId;

  struct HTTPResponse
  {
    uint32_t status = 0;
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";

    std::vector<uint8_t> get_header_data(
      const std::string& name, bool url_decoded = false) const;

    std::string get_header_string(
      const std::string& name, bool url_decoded = false) const;
  };

  struct HTTPRequest
  {
    HTTPRequest() {}
    HTTPRequest(const std::string& url) : url(url) {}
    virtual ~HTTPRequest() = default;

    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";
  };

  typedef std::vector<HTTPRequest> HTTPRequests;
  typedef std::vector<HTTPResponse> HTTPResponses;

  class HTTPClient
  {
  public:
    HTTPClient(
      size_t request_timeout = 0,
      size_t max_attempts = 5,
      bool verbose = false) :
      request_timeout(request_timeout),
      max_attempts(max_attempts),
      verbose(verbose)
    {}
    virtual ~HTTPClient() = default;

    virtual HTTPRequestSetId submit(
      HTTPRequests&& rs, std::function<void(HTTPResponses&&)>&& callback) = 0;

    virtual bool is_complete(const HTTPRequestSetId& id) const = 0;

    virtual void erase(const HTTPRequestSetId& id) = 0;

  protected:
    size_t request_timeout = 0;
    size_t max_attempts = 5;
    bool verbose = false;
  };

  class SynchronousHTTPClient : public HTTPClient
  {
  public:
    SynchronousHTTPClient(
      size_t request_timeout = 0,
      size_t max_attempts = 5,
      bool verbose = false);
    virtual ~SynchronousHTTPClient() = default;

    virtual HTTPRequestSetId submit(
      HTTPRequests&& rs,
      std::function<void(HTTPResponses&&)>&& callback) override;

    virtual bool is_complete(const HTTPRequestSetId& id) const override;

    static HTTPResponse execute_synchronous(
      const HTTPRequest& request,
      size_t timeout = 0,
      size_t max_attempts = 5,
      bool verbose = false);

    virtual void erase(const HTTPRequestSetId& id) override;

  protected:
    std::unordered_map<HTTPRequestSetId, HTTPRequests> request_sets;
    std::unordered_map<HTTPRequestSetId, HTTPResponses> response_sets;
  };

  class AsynchronousHTTPClient : public HTTPClient
  {
  public:
    AsynchronousHTTPClient(
      size_t request_timeout = 0,
      size_t max_attempts = 5,
      bool verbose = false);
    virtual ~AsynchronousHTTPClient();

    virtual HTTPRequestSetId submit(
      HTTPRequests&& rs,
      std::function<void(HTTPResponses&&)>&& callback) override;

    virtual bool is_complete(const HTTPRequestSetId& id) const override;

    virtual void erase(const HTTPRequestSetId& id) override;

  private:
    void* implementation;
  };

  inline std::vector<uint8_t> url_decode(const std::string& in)
  {
    char* decoded = url_decode(in.data(), in.size());
    int len = strlen(decoded);
    if (!decoded)
      throw std::bad_alloc();
    std::vector<uint8_t> r = {decoded, decoded + len};
    free(decoded);
    return r;
  }

  inline std::vector<uint8_t> HTTPResponse::get_header_data(
    const std::string& name, bool url_decoded) const
  {
    auto hit = headers.find(name);
    if (hit == headers.end())
    {
      std::string lname = name;
      std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
      hit = headers.find(lname);
      if (hit == headers.end())
        throw std::runtime_error("missing response header '" + name + "'");
    }
    if (url_decoded)
      return url_decode(hit->second);
    else
      return {hit->second.data(), hit->second.data() + hit->second.size()};
  }

  inline std::string HTTPResponse::get_header_string(
    const std::string& name, bool url_decoded) const
  {
    auto t = get_header_data(name, url_decoded);
    return std::string(t.begin(), t.end());
  }
}

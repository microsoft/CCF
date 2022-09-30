// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
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

    static std::vector<uint8_t> url_decode(const std::string& in);
  };

  struct HTTPRequest
  {
    HTTPRequest() {}
    HTTPRequest(const std::string& url) : url(url) {}
    virtual ~HTTPRequest() = default;

    std::string url = "";
    std::unordered_map<std::string, std::string> headers = {};
    std::string body = "";
    size_t max_attempts = 5;

    HTTPResponse execute(
      size_t timeout = 0, bool verbose = false); /// synchronous
  };

  typedef std::vector<HTTPRequest> HTTPRequests;
  typedef std::vector<HTTPResponse> HTTPResponses;

  class HTTPClient
  {
  public:
    HTTPClient(size_t request_timeout = 0, bool verbose = false) :
      request_timeout(request_timeout),
      verbose(verbose)
    {}
    virtual ~HTTPClient() = default;

    virtual HTTPRequestSetId submit(
      HTTPRequests&& rs, std::function<void(HTTPResponses&&)>&& callback) = 0;

    virtual bool is_complete(const HTTPRequestSetId& id) const = 0;

  protected:
    size_t request_timeout = 0;
    bool verbose = false;
  };

  class SynchronousHTTPClient : public HTTPClient
  {
  public:
    SynchronousHTTPClient(size_t request_timeout = 0, bool verbose = false);
    virtual ~SynchronousHTTPClient() = default;

    virtual HTTPRequestSetId submit(
      HTTPRequests&& rs,
      std::function<void(HTTPResponses&&)>&& callback) override;

    virtual bool is_complete(const HTTPRequestSetId& id) const override;

  protected:
    std::unordered_map<HTTPRequestSetId, HTTPRequests> request_sets;
    std::unordered_map<HTTPRequestSetId, HTTPResponses> response_sets;
  };

  class AsynchronousHTTPClient : public HTTPClient
  {
  public:
    AsynchronousHTTPClient(size_t request_timeout = 0, bool verbose = false);
    virtual ~AsynchronousHTTPClient();

    virtual HTTPRequestSetId submit(
      HTTPRequests&& rs,
      std::function<void(HTTPResponses&&)>&& callback) override;

    virtual bool is_complete(const HTTPRequestSetId& id) const override;

  private:
    void* implementation;
  };
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/http_client.h"

#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  namespace
  {
    // From http://www.geekhideout.com/urlcode.shtml

    /* Converts a hex character to its integer value */
    char from_hex(char ch)
    {
      return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
    }

    /* Returns a url-decoded version of str */
    /* IMPORTANT: be sure to free() the returned string after use */
    char* url_decode(const char* str, size_t len)
    {
      const char* pstr = str;
      char *buf = (char*)malloc(len + 1), *pbuf = buf;
      while (*pstr)
      {
        if (*pstr == '%')
        {
          if (pstr[1] && pstr[2])
          {
            *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
            pstr += 2;
          }
        }
        else if (*pstr == '+')
        {
          *pbuf++ = ' ';
        }
        else
        {
          *pbuf++ = *pstr;
        }
        pstr++;
      }
      *pbuf = '\0';
      return buf;
    }
  }

  std::vector<uint8_t> HTTPResponse::url_decode(const std::string& in)
  {
    char* decoded = ravl::url_decode(in.data(), in.size());
    int len = strlen(decoded);
    if (!decoded)
      throw std::bad_alloc();
    std::vector<uint8_t> r = {decoded, decoded + len};
    free(decoded);
    return r;
  }

  std::vector<uint8_t> HTTPResponse::get_header_data(
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

  std::string HTTPResponse::get_header_string(
    const std::string& name, bool url_decoded) const
  {
    auto t = get_header_data(name, url_decoded);
    return std::string(t.begin(), t.end());
  }

  SynchronousHTTPClient::SynchronousHTTPClient(
    size_t request_timeout, bool verbose) :
    HTTPClient(request_timeout, verbose)
  {}

  HTTPRequestSetId SynchronousHTTPClient::submit(
    HTTPRequests&& rs, std::function<void(HTTPResponses&&)>&& callback)
  {
    HTTPRequestSetId id = request_sets.size();
    size_t sz = rs.size();

    request_sets.emplace(id, std::move(rs));
    auto [rit, ok] = response_sets.emplace(id, HTTPResponses(sz));

    if (!ok)
      throw std::bad_alloc();

    auto rsit = request_sets.find(id);
    for (size_t i = 0; i < rsit->second.size(); i++)
    {
      auto& request = rsit->second.at(i);
      HTTPResponse response = request.execute(request_timeout, verbose);
      response_sets[id][i] = response;

      if (response.status != 200)
        throw std::runtime_error(
          fmt::format("unexpected HTTP status {}", response.status));
    }

    HTTPResponses r;
    r.swap(rit->second);
    callback(std::move(r));
    response_sets.erase(rit);

    return id;
  }

  bool SynchronousHTTPClient::is_complete(const HTTPRequestSetId&) const
  {
    return true;
  }
}
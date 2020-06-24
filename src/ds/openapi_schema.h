// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "ds/nonstd.h"

#include <http-parser/http_parser.h>
#include <nlohmann/json.hpp>
#include <string>

namespace ds
{
  /**
   * These structs contain the required fields to build the corresponding
   * OpenAPI objects. They do not contain every field, but should be trivially
   * extensible with any which are desired.
   */
  namespace openapi
  {
    struct Info
    {
      std::string title;
      std::string description;
      std::string version;
    };
    DECLARE_JSON_TYPE(Info);
    DECLARE_JSON_REQUIRED_FIELDS(Info, title, description, version);

    struct Server
    {
      std::string url;

      bool operator==(const Server& rhs) const
      {
        return url == rhs.url;
      }
    };
    DECLARE_JSON_TYPE(Server);
    DECLARE_JSON_REQUIRED_FIELDS(Server, url);

    struct Response
    {
      std::string description;
    };
    DECLARE_JSON_TYPE(Response);
    DECLARE_JSON_REQUIRED_FIELDS(Response, description);

    // Keys are really 'default' or a HTTP status code, but this is a quick
    // approximation
    using Responses = std::map<std::string, Response>;

    struct Operation
    {
      Responses responses;
    };
    DECLARE_JSON_TYPE(Operation);
    DECLARE_JSON_REQUIRED_FIELDS(Operation, responses);

    struct PathItem
    {
      std::map<http_method, Operation> operations;
    };

    inline void to_json(nlohmann::json& j, const PathItem& pi)
    {
      j = nlohmann::json::object();
      for (const auto method : {HTTP_GET, HTTP_PUT, HTTP_POST, HTTP_DELETE})
      {
        const auto it = pi.operations.find(method);
        if (it != pi.operations.end())
        {
          std::string method_s = http_method_str(method);
          nonstd::to_lower(method_s);
          j[method_s] = it->second;
        }
      }
    }

    // TODO: This is a duplicate
    static http_method http_method_from_str(const char* s)
    {
#define XX(num, name, string) \
  if (strcmp(s, #string) == 0) \
  { \
    return http_method(num); \
  }
      HTTP_METHOD_MAP(XX)
#undef XX

      throw std::logic_error(fmt::format("Unknown HTTP method '{}'", s));
    }

    inline void from_json(const nlohmann::json& j, PathItem& pi)
    {
      for (auto it = j.begin(); it != j.end(); ++it)
      {
        const auto method = http_method_from_str(it.key().c_str());
        pi.operations[method] = it.value();
      }
    }

    using Paths = std::map<std::string, PathItem>;

    struct Document
    {
      std::string openapi = "3.0.0";
      Info info;
      std::vector<Server> servers;
      Paths paths;
    };
    DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Document);
    DECLARE_JSON_REQUIRED_FIELDS(Document, openapi, info, paths);
    DECLARE_JSON_OPTIONAL_FIELDS(Document, servers);
  }
}

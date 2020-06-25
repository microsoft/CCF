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

    inline void to_json(nlohmann::json& j, const http_status& status)
    {
      j = std::to_string(status);
    }

    inline void from_json(const nlohmann::json& j, http_status& status)
    {
      const auto s = j.get<std::string>();

#define XX(num, name, string) \
  if (s == #num) \
  { \
    status = HTTP_STATUS_##name; \
  } \
  else

      HTTP_STATUS_MAP(XX)
      // else
      {
        throw std::runtime_error(
          fmt::format("Unrecognsied key in OpenAPI Responses Object: {}", s));
      }
#undef XX
    }

    inline void fill_enum_schema(nlohmann::json& j, const http_status&)
    {
      auto enums = nlohmann::json::array();

#define XX(num, name, string) enums.push_back(std::to_string(num));
      HTTP_STATUS_MAP(XX);
#undef XX

      j["enum"] = enums;
    }

    struct Operation
    {
      std::map<http_status, Response> responses;
    };
    DECLARE_JSON_TYPE(Operation);
    DECLARE_JSON_REQUIRED_FIELDS(Operation, responses);

    inline void to_json(nlohmann::json& j, const http_method& verb)
    {
      std::string verb_s = http_method_str(verb);
      nonstd::to_lower(verb_s);
      j = verb_s;
    }

    inline void from_json(const nlohmann::json& j, http_method& verb)
    {
      const auto s = j.get<std::string>();
      if (s == "get")
      {
        verb = HTTP_GET;
      }
      else if (s == "put")
      {
        verb = HTTP_PUT;
      }
      else if (s == "post")
      {
        verb = HTTP_POST;
      }
      else if (s == "delete")
      {
        verb = HTTP_DELETE;
      }
      else
      {
        throw std::runtime_error(
          fmt::format("Unexpected key in OpenAPI Path Item: {}", s));
      }
    }

    inline void fill_enum_schema(nlohmann::json& j, const http_method&)
    {
      auto enums = nlohmann::json::array();
      enums.push_back("get");
      enums.push_back("put");
      enums.push_back("post");
      enums.push_back("delete");
      j["enum"] = enums;
    }

    struct PathItem
    {
      std::map<http_method, Operation> operations;
    };
    DECLARE_JSON_TYPE(PathItem);
    DECLARE_JSON_REQUIRED_FIELDS(PathItem, operations);

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

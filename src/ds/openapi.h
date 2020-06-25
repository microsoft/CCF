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

    struct Operation
    {
      std::map<std::string, Response> responses;

      Response& operator[](http_status status)
      {
        // HTTP_STATUS_OK (aka an int with value 200) becomes the string "200"
        const auto s = std::to_string(status);
        return responses[s];
      }
    };
    DECLARE_JSON_TYPE(Operation);
    DECLARE_JSON_REQUIRED_FIELDS(Operation, responses);

    struct PathItem
    {
      std::map<std::string, Operation> operations;

      Operation& operator[](http_method verb)
      {
        // HTTP_GET becomes the string "get"
        std::string s = http_method_str(verb);
        nonstd::to_lower(s);
        return operations[s];
      }
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

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/endpoint.h"

#include <map>
#include <string>

namespace ccf::js
{
  struct Metadata
  {
    std::map<
      std::string,
      std::map<std::string, ccf::endpoints::EndpointProperties>>
      endpoints;
  };
  DECLARE_JSON_TYPE(Metadata);
  DECLARE_JSON_REQUIRED_FIELDS(Metadata, endpoints);

  struct ModuleDef
  {
    std::string name;
    std::string module;
  };
  DECLARE_JSON_TYPE(ModuleDef);
  DECLARE_JSON_REQUIRED_FIELDS(ModuleDef, name, module);

  struct Bundle
  {
    std::vector<ModuleDef> modules;
    Metadata metadata;
  };

  DECLARE_JSON_TYPE(Bundle);
  DECLARE_JSON_REQUIRED_FIELDS(Bundle, modules, metadata);
}

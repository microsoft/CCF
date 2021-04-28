// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <string>

namespace crypto
{
  struct SubjectAltName
  {
    std::string san;
    bool is_ip;
  };
  DECLARE_JSON_TYPE(SubjectAltName);
  DECLARE_JSON_REQUIRED_FIELDS(SubjectAltName, san, is_ip);
}

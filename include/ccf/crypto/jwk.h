// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <string>

namespace crypto
{
  // TODO: Refactor with existing JWT stuff
  struct JsonWebKeyBase
  {
    std::string kty;
    std::string kid;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(JsonWebKeyBase);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyBase, kty);
  DECLARE_JSON_OPTIONAL_FIELDS(JsonWebKeyBase, kid);

  struct JsonWebKeyEC : JsonWebKeyBase
  {
    std::string crv;
    std::string x;
    std::string y;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyEC, JsonWebKeyBase);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyEC, crv, x, y);

  struct JsonWebKeyRSA : JsonWebKeyBase
  {
    std::string alg;
    std::string n;
    std::string e;
  };
  DECLARE_JSON_TYPE_WITH_BASE(JsonWebKeyRSA, JsonWebKeyBase);
  DECLARE_JSON_REQUIRED_FIELDS(JsonWebKeyRSA, alg, n, e);
}
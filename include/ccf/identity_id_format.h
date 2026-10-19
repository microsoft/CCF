// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

namespace ccf
{
  enum class IdentityIdFormat
  {
    SHA256,
    DIDKey
  };

  DECLARE_JSON_ENUM(
    IdentityIdFormat,
    {{IdentityIdFormat::SHA256, "sha256"},
     {IdentityIdFormat::DIDKey, "did:key"}});
}

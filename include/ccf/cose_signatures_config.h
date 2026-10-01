// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"

#include <string>

namespace ccf
{
  struct COSESignaturesConfig
  {
    std::string issuer;
    std::string subject;

    bool operator==(const COSESignaturesConfig& other) const = default;
  };

  DECLARE_JSON_TYPE(COSESignaturesConfig);
  DECLARE_JSON_REQUIRED_FIELDS(COSESignaturesConfig, issuer, subject);
}

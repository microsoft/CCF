// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"

#include <map>
#include <string>

namespace ccf
{
  struct SigningKeyType
  {
    static constexpr auto CLASSICAL = "CLASSICAL";
  };

  using ServiceSigningKeys = std::map<std::string, ccf::crypto::Pem>;
}

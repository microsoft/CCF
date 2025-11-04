// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/rsa_public_key.h"

#include <variant>

namespace ccf::crypto
{
  using InvalidKeyPtr = size_t*;

  template <typename... Ts>
  using KeyVariant = std::variant<Ts..., InvalidKeyPtr>;
}
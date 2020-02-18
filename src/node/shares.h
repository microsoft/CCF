// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

#include <msgpack-c/msgpack.hpp>
#include <vector>

namespace ccf
{
  using KeyShareIndex = ObjectId;

  struct KeyShareInfo
  {
    std::vector<uint8_t> encrypted_ledger_secret;
    std::vector<std::vector<uint8_t>> encrypted_shares;

    MSGPACK_DEFINE(encrypted_ledger_secret, encrypted_shares);
  };

  DECLARE_JSON_TYPE(KeyShareInfo)
  DECLARE_JSON_REQUIRED_FIELDS(
    KeyShareInfo, encrypted_ledger_secret, encrypted_shares)

  using Shares = Store::Map<KeyShareIndex, KeyShareInfo>;
}
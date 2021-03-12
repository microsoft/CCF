// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/pem.h"
#include "service_map.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct UserInfo
  {
    crypto::Pem cert;
    nlohmann::json user_data = nullptr;

    MSGPACK_DEFINE(cert, user_data);
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(UserInfo);
  DECLARE_JSON_REQUIRED_FIELDS(UserInfo, cert);
  DECLARE_JSON_OPTIONAL_FIELDS(UserInfo, user_data);

  // TODO:
  // Changing this to JSON value causes a 30% drop of performance in SB perf
  // test
  // Options:
  // 1. Use raw serialiaser for this (not great for audit, awkward to serialise)
  // 2. Split table, and use raw for cert
  // using Users = kv::Map<UserId, UserInfo>;
  using Users = ServiceMap<UserId, UserInfo>;
}
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

  using Users = kv::Map<UserId, UserInfo>;
}
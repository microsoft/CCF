// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "entities.h"

namespace ccf
{
  struct UserInfo
  {
    std::vector<uint8_t> cert;

    MSGPACK_DEFINE(cert);
  };
  DECLARE_JSON_TYPE(UserInfo);
  DECLARE_JSON_REQUIRED_FIELDS(UserInfo, cert);

  using Users = Store::Map<UserId, UserInfo>;
}
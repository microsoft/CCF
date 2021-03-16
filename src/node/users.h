// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/pem.h"
#include "service_map.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  // TODO: Move to other file
  struct NewUser
  {
    crypto::Pem cert;
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NewUser)
  DECLARE_JSON_REQUIRED_FIELDS(NewUser, cert)
  DECLARE_JSON_OPTIONAL_FIELDS(NewUser, user_data)

  using UserCerts = kv::RawCopySerialisedMap<UserId, crypto::Pem>;

  // TODO: Use this type in UserInfo table!
  // struct UserInfo
  // {
  //   nlohmann::json user_data = nullptr;
  // };

  using UserData = ServiceMap<UserId, nlohmann::json>;
}
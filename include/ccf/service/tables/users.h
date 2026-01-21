// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/service/blit_serialiser_pem.h"
#include "ccf/service/map.h"

#include <nlohmann/json.hpp>

namespace ccf
{
  struct NewUser
  {
    ccf::crypto::Pem cert;
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(NewUser);
  DECLARE_JSON_REQUIRED_FIELDS(NewUser, cert);
  DECLARE_JSON_OPTIONAL_FIELDS(NewUser, user_data);

  struct UserDetails
  {
    /** Free-form user data, useful to store role information about users for
        example. */
    nlohmann::json user_data = nullptr;
  };
  DECLARE_JSON_TYPE(UserDetails);
  DECLARE_JSON_REQUIRED_FIELDS(UserDetails, user_data);

  using UserCerts = ccf::kv::RawCopySerialisedMap<UserId, ccf::crypto::Pem>;
  using UserInfo = ServiceMap<UserId, UserDetails>;

  namespace Tables
  {
    static constexpr auto USER_CERTS = "public:ccf.gov.users.certs";
    static constexpr auto USER_INFO = "public:ccf.gov.users.info";
  }
}
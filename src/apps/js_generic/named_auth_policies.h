// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "node/rpc/endpoint_registry.h"

namespace ccfapp
{
  static std::shared_ptr<ccf::AuthnPolicy> get_policy_by_name(const std::string& name)
  {
    if (name == "user_cert")
    {
      return ccf::user_cert_auth_policy;
    }
    if (name == "user_sig")
    {
      return ccf::user_signature_auth_policy;
    }
    if (name == "member_cert")
    {
      return ccf::member_cert_auth_policy;
    }
    if (name == "member_sig")
    {
      return ccf::member_signature_auth_policy;
    }
    if (name == "jwt")
    {
      return ccf::jwt_auth_policy;
    }
    if (name == "no_auth")
    {
      return ccf::empty_auth_policy;
    }
    return nullptr;
  }
}
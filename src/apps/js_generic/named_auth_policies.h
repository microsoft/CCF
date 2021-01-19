// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "node/rpc/endpoint_registry.h"

namespace ccfapp
{
  namespace
  {
    constexpr auto POLICY_NAME_USER_CERT = "user_cert";
    constexpr auto POLICY_NAME_USER_SIG = "user_sig";
    constexpr auto POLICY_NAME_MEMBER_CERT = "member_cert";
    constexpr auto POLICY_NAME_MEMBER_SIG = "member_sig";
    constexpr auto POLICY_NAME_JWT = "jwt";
    constexpr auto POLICY_NAME_EMPTY = "no_auth";
  }

  static std::shared_ptr<ccf::AuthnPolicy> get_policy_by_name(
    const std::string& name)
  {
    if (name == POLICY_NAME_USER_CERT)
    {
      return ccf::user_cert_auth_policy;
    }
    if (name == POLICY_NAME_USER_SIG)
    {
      return ccf::user_signature_auth_policy;
    }
    if (name == POLICY_NAME_MEMBER_CERT)
    {
      return ccf::member_cert_auth_policy;
    }
    if (name == POLICY_NAME_MEMBER_SIG)
    {
      return ccf::member_signature_auth_policy;
    }
    if (name == POLICY_NAME_JWT)
    {
      return ccf::jwt_auth_policy;
    }
    if (name == POLICY_NAME_EMPTY)
    {
      return ccf::empty_auth_policy;
    }
    return nullptr;
  }

  template <typename T>
  constexpr char const* get_policy_name_from_ident(const T*)
  {
    if constexpr (std::is_same_v<T, ccf::UserCertAuthnIdentity>)
    {
      return POLICY_NAME_USER_CERT;
    }
    else if constexpr (std::is_same_v<T, ccf::UserSignatureAuthnIdentity>)
    {
      return POLICY_NAME_USER_SIG;
    }
    else if constexpr (std::is_same_v<T, ccf::MemberCertAuthnIdentity>)
    {
      return POLICY_NAME_MEMBER_CERT;
    }
    else if constexpr (std::is_same_v<T, ccf::MemberSignatureAuthnIdentity>)
    {
      return POLICY_NAME_MEMBER_SIG;
    }
    else if constexpr (std::is_same_v<T, ccf::JwtAuthnIdentity>)
    {
      return POLICY_NAME_JWT;
    }
    else if constexpr (std::is_same_v<T, ccf::EmptyAuthnIdentity>)
    {
      return POLICY_NAME_EMPTY;
    }
    else
    {
      return nullptr;
    }
  }
}
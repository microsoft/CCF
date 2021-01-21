// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "node/rpc/endpoint_registry.h"

namespace ccfapp
{
  static std::shared_ptr<ccf::AuthnPolicy> get_policy_by_name(
    const std::string& name)
  {
    if (name == ccf::UserCertAuthnPolicy::SECURITY_SCHEME_NAME)
    {
      return ccf::user_cert_auth_policy;
    }
    if (name == ccf::UserSignatureAuthnPolicy::SECURITY_SCHEME_NAME)
    {
      return ccf::user_signature_auth_policy;
    }
    if (name == ccf::MemberCertAuthnPolicy::SECURITY_SCHEME_NAME)
    {
      return ccf::member_cert_auth_policy;
    }
    if (name == ccf::MemberSignatureAuthnPolicy::SECURITY_SCHEME_NAME)
    {
      return ccf::member_signature_auth_policy;
    }
    if (name == ccf::JwtAuthnPolicy::SECURITY_SCHEME_NAME)
    {
      return ccf::jwt_auth_policy;
    }
    if (name == ccf::EmptyAuthnPolicy::SECURITY_SCHEME_NAME)
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
      return ccf::UserCertAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::UserSignatureAuthnIdentity>)
    {
      return ccf::UserSignatureAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::MemberCertAuthnIdentity>)
    {
      return ccf::MemberCertAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::MemberSignatureAuthnIdentity>)
    {
      return ccf::MemberSignatureAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::JwtAuthnIdentity>)
    {
      return ccf::JwtAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::EmptyAuthnIdentity>)
    {
      return ccf::EmptyAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else
    {
      return nullptr;
    }
  }
}
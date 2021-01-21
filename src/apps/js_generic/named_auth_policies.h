// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "node/rpc/endpoint_registry.h"

namespace ccfapp
{
  using NamedAuthPolicies =
    std::unordered_map<std::string, std::shared_ptr<ccf::AuthnPolicy>>;

  static NamedAuthPolicies& auth_policies_by_name()
  {
    static NamedAuthPolicies policies;
    if (policies.empty())
    {
      policies.emplace(
        ccf::UserCertAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::user_cert_auth_policy);
      policies.emplace(
        ccf::UserSignatureAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::user_signature_auth_policy);

      policies.emplace(
        ccf::MemberCertAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::member_cert_auth_policy);
      policies.emplace(
        ccf::MemberSignatureAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::member_signature_auth_policy);

      policies.emplace(
        ccf::JwtAuthnPolicy::SECURITY_SCHEME_NAME, ccf::jwt_auth_policy);

      policies.emplace(
        ccf::EmptyAuthnPolicy::SECURITY_SCHEME_NAME, ccf::empty_auth_policy);
    }

    return policies;
  }

  static std::shared_ptr<ccf::AuthnPolicy> get_policy_by_name(
    const std::string& name)
  {
    auto& policies = auth_policies_by_name();
    auto it = policies.find(name);
    if (it == policies.end())
    {
      return nullptr;
    }

    return it->second;
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
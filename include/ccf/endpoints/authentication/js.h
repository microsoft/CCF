// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/common_auth_policies.h"
#include "ccf/endpoint.h"
#include "ccf/endpoints/authentication/all_of_auth.h"

namespace ccf
{
  using NamedAuthPolicies =
    std::unordered_map<std::string, std::shared_ptr<ccf::AuthnPolicy>>;

  static inline NamedAuthPolicies& auth_policies_by_name()
  {
    static NamedAuthPolicies policies;
    if (policies.empty())
    {
      policies.emplace(
        ccf::UserCertAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::user_cert_auth_policy);

      policies.emplace(
        ccf::MemberCertAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::member_cert_auth_policy);

      policies.emplace(
        ccf::AnyCertAuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::any_cert_auth_policy);

      policies.emplace(
        ccf::JwtAuthnPolicy::SECURITY_SCHEME_NAME, ccf::jwt_auth_policy);

      policies.emplace(
        ccf::UserCOSESign1AuthnPolicy::SECURITY_SCHEME_NAME,
        ccf::user_cose_sign1_auth_policy);

      policies.emplace(
        ccf::EmptyAuthnPolicy::SECURITY_SCHEME_NAME, ccf::empty_auth_policy);
    }

    return policies;
  }

  static inline std::shared_ptr<ccf::AuthnPolicy> get_policy_by_name(
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
  static constexpr char const* get_policy_name_from_ident(const T* /*unused*/)
  {
    if constexpr (std::is_same_v<T, ccf::UserCertAuthnIdentity>)
    {
      return ccf::UserCertAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::MemberCertAuthnIdentity>)
    {
      return ccf::MemberCertAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::AnyCertAuthnIdentity>)
    {
      return ccf::AnyCertAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::JwtAuthnIdentity>)
    {
      return ccf::JwtAuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::UserCOSESign1AuthnIdentity>)
    {
      return ccf::UserCOSESign1AuthnPolicy::SECURITY_SCHEME_NAME;
    }
    else if constexpr (std::is_same_v<T, ccf::MemberCOSESign1AuthnIdentity>)
    {
      return ccf::MemberCOSESign1AuthnPolicy::SECURITY_SCHEME_NAME;
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

  static inline void instantiate_authn_policies(
    ccf::endpoints::EndpointDefinition& endpoint)
  {
    for (const auto& policy_desc : endpoint.properties.authn_policies)
    {
      if (policy_desc.is_string())
      {
        const auto policy_name = policy_desc.get<std::string>();
        auto policy = get_policy_by_name(policy_name);
        if (policy == nullptr)
        {
          throw std::logic_error(
            fmt::format("Unknown auth policy: {}", policy_name));
        }
        endpoint.authn_policies.push_back(std::move(policy));
      }
      else
      {
        if (policy_desc.is_object())
        {
          const auto it = policy_desc.find("all_of");
          if (it != policy_desc.end())
          {
            if (it.value().is_array())
            {
              std::vector<std::shared_ptr<ccf::AuthnPolicy>>
                constituent_policies;
              for (const auto& val : it.value())
              {
                if (!val.is_string())
                {
                  constituent_policies.clear();
                  break;
                }

                const auto policy_name = val.get<std::string>();
                auto policy = get_policy_by_name(policy_name);
                if (policy == nullptr)
                {
                  throw std::logic_error(
                    fmt::format("Unknown auth policy: {}", policy_name));
                }
                constituent_policies.push_back(std::move(policy));
              }

              if (!constituent_policies.empty())
              {
                endpoint.authn_policies.push_back(
                  std::make_shared<ccf::AllOfAuthnPolicy>(
                    constituent_policies));
                continue;
              }
            }
          }
        }

        // Any failure in above checks falls through to this detailed error.
        throw std::logic_error(fmt::format(
          "Unsupported auth policy. Policies must be either a string, or an "
          "object containing an \"all_of\" key with list-of-strings value. "
          "Unsupported value: {}",
          policy_desc.dump()));
      }
    }
  }
}
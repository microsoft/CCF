// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/all_of_auth.h"

#include "ccf/ds/nonstd.h"

namespace ccf
{
  std::string AllOfAuthnIdentity::get_conjoined_name() const
  {
    std::string scheme_name;
    for (const auto& [ident_name, _] : identities)
    {
      if (!scheme_name.empty())
      {
        scheme_name += "+";
      }

      scheme_name += ident_name;
    }
    return scheme_name;
  }

  std::string get_combined_schema_name(
    const AllOfAuthnPolicy::Policies& policies)
  {
    std::string scheme_name;
    for (const auto& [policy_name, _] : policies)
    {
      if (!scheme_name.empty())
      {
        scheme_name += "+";
      }

      scheme_name += policy_name;
    }
    return scheme_name;
  }

  AllOfAuthnPolicy::AllOfAuthnPolicy(Policies _policies) :
    policies(std::move(_policies))
  {
    scheme_name = get_combined_schema_name(policies);
  }

  AllOfAuthnPolicy::AllOfAuthnPolicy(
    const std::vector<std::shared_ptr<AuthnPolicy>>& _policies)
  {
    for (auto policy : _policies)
    {
      const auto policy_name = policy->get_security_scheme_name();
      const auto ib = policies.try_emplace(policy_name, policy);

      if (!ib.second)
      {
        throw std::runtime_error(fmt::format(
          "AND authentication policy contains duplicate policies identified "
          "by {} (policy = {})",
          policy_name,
          scheme_name));
      }
    }

    scheme_name = get_combined_schema_name(policies);
  }

  std::unique_ptr<AuthnIdentity> AllOfAuthnPolicy::authenticate(
    ccf::kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    auto result = std::make_unique<AllOfAuthnIdentity>();

    for (auto& [policy_name, policy] : policies)
    {
      auto ident = policy->authenticate(tx, ctx, error_reason);
      if (ident != nullptr)
      {
        const auto ib =
          result->identities.try_emplace(policy_name, std::move(ident));
        if (!ib.second)
        {
          throw std::runtime_error(fmt::format(
            "AND authentication policy contains duplicate policies identified "
            "by {} (policy = {})",
            policy_name,
            scheme_name));
        }
      }
      else
      {
        // Bury the failing policy's name in the error reason, so we can ask it
        // to populate the unauthenticated error later
        error_reason = fmt::format("{}:{}", policy_name, error_reason);
        return nullptr;
      }
    }

    return result;
  }

  void AllOfAuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    auto [pn, er] = ccf::nonstd::split_1(error_reason, ":");

    std::string policy_name(pn);
    auto it = policies.find(policy_name);
    if (it == policies.end())
    {
      throw std::runtime_error(fmt::format(
        "AND authentication asked to construct error for sub-policy {}, which "
        "is not a recognised member (policy = {})",
        policy_name,
        scheme_name));
    }

    error_reason = std::string(er);

    it->second->set_unauthenticated_error(ctx, std::move(error_reason));
  }

  std::optional<OpenAPISecuritySchema> AllOfAuthnPolicy::
    get_openapi_security_schema() const
  {
    return std::nullopt;
  }

  std::string AllOfAuthnPolicy::get_security_scheme_name()
  {
    return scheme_name;
  }
}

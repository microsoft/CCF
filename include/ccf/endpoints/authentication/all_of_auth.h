// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"

#include <map>

namespace ccf
{
  // To require _multiple_ authentication types, a conjoined policy can be
  // formed. It will pass if and only if all of its member policies pass, and
  // return all of their extracted identities.
  struct AllOfAuthnIdentity : public AuthnIdentity
  {
    std::map<std::string, std::unique_ptr<AuthnIdentity>> identities;

    std::string get_conjoined_name() const;
  };

  class AllOfAuthnPolicy : public AuthnPolicy
  {
  public:
    using Policies = std::map<std::string, std::shared_ptr<AuthnPolicy>>;

  private:
    Policies policies;
    std::string scheme_name;

  public:
    AllOfAuthnPolicy(const Policies& _policies);

    // Try using schema_name as key
    AllOfAuthnPolicy(
      const std::vector<std::shared_ptr<AuthnPolicy>>& _policies);

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx&,
      const std::shared_ptr<ccf::RpcContext>&,
      std::string&) override;

    void set_unauthenticated_error(
      std::shared_ptr<ccf::RpcContext>, std::string&&) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override;

    std::string get_security_scheme_name() override;
  };
}

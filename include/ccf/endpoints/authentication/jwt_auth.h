// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/authentication_types.h"

namespace ccf
{
  struct JwtAuthnIdentity : public AuthnIdentity
  {
    /** JWT key issuer, as defined in @c
     * public:ccf.gov.jwt_public_signing_key_issuer */
    std::string key_issuer;
    /** JWT header */
    nlohmann::json header;
    /** JWT payload */
    nlohmann::json payload;
  };

  struct PublicKeysCache;

  bool validate_issuer(
    const std::string& iss,
    const std::optional<std::string>& tid,
    std::string constraint);

  class JwtAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;
    std::unique_ptr<PublicKeysCache> keys_cache;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "jwt";

    JwtAuthnPolicy();
    ~JwtAuthnPolicy() override;

    std::unique_ptr<AuthnIdentity> authenticate(
      ccf::kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    void set_unauthenticated_error(
      std::shared_ptr<ccf::RpcContext> ctx,
      std::string&& error_reason) override;

    [[nodiscard]] std::optional<OpenAPISecuritySchema>
    get_openapi_security_schema() const override
    {
      return security_schema;
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    }
  };
}

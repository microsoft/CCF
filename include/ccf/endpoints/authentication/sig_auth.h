// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/entity_id.h"
#include "ccf/service/signed_req.h"

namespace ccf
{
  struct UserSignatureAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID */
    UserId user_id;
    /** User certificate, used to sign this request, described by keyId */
    crypto::Pem user_cert;
    /** Canonicalised request and associated signature */
    SignedReq signed_request;
  };

  struct VerifierCache;

  class UserSignatureAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;
    std::unique_ptr<VerifierCache> verifiers;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "user_signature";

    UserSignatureAuthnPolicy();
    virtual ~UserSignatureAuthnPolicy();

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    void set_unauthenticated_error(
      std::shared_ptr<ccf::RpcContext> ctx,
      std::string&& error_reason) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return security_schema;
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    }
  };

  struct MemberSignatureAuthnIdentity : public AuthnIdentity
  {
    /** CCF member ID */
    MemberId member_id;

    /** Member certificate, used to sign this request, described by keyId */
    crypto::Pem member_cert;

    /** Canonicalised request and associated signature */
    SignedReq signed_request;

    /** Digest of request */
    std::vector<uint8_t> request_digest;
  };

  class MemberSignatureAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;
    std::unique_ptr<VerifierCache> verifiers;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_signature";

    MemberSignatureAuthnPolicy();
    virtual ~MemberSignatureAuthnPolicy();

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    void set_unauthenticated_error(
      std::shared_ptr<ccf::RpcContext> ctx,
      std::string&& error_reason) override;

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return security_schema;
    }

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    }
  };
}

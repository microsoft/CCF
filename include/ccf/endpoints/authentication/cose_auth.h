// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/entity_id.h"
#include "ccf/service/signed_req.h"

namespace ccf
{
  struct MemberCOSESign1AuthnIdentity : public AuthnIdentity
  {
    /** CCF member ID */
    MemberId member_id;

    /** Member certificate, used to sign this request, described by keyId */
    crypto::Pem member_cert;

    /** COSE Protected Headers */
    /** COSE Payload */
    /** COSE Signature */
  };

  class MemberCOSESign1AuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_cose_sign1";

    MemberCOSESign1AuthnPolicy();
    ~MemberCOSESign1AuthnPolicy();

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

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/endpoints/authentication/authentication_types.h"
#include "ccf/entity_id.h"
#include "ccf/service/signed_req.h"

namespace ccf
{
  struct ProtectedHeader
  {
    int64_t alg;
    std::optional<std::string> kid;
    std::optional<std::string> gov_msg_type;
    std::optional<std::string> gov_msg_proposal_id;
    std::optional<std::string> gov_msg_member_id;
    uint64_t gov_msg_created_at;
  };

  struct MemberCOSESign1AuthnIdentity : public AuthnIdentity
  {
    /** CCF member ID */
    MemberId member_id;

    /** Member certificate, used to sign this request, described by keyId */
    crypto::Pem member_cert;

    /** COSE Protected Header */
    ProtectedHeader protected_header;

    /** COSE Content */
    std::span<const uint8_t> content;

    /** COSE Envelope
     *
     * This contains the payload at the moment, but that will be removed
     * in later versions to be an envelope with detached content.
     */
    std::span<const uint8_t> envelope;

    /** COSE Signature */
    std::span<const uint8_t> signature;
  };

  /** Experimental COSE Sign1 Authentication Policy
   *
   * Allows ccf.gov.msg.type and ccf.gov.msg.proposal_id protected header
   * entries, to specify the type of governance action, and which proposal
   * it refers to. The plan is to offer this authentication method as an
   * alternative to MemberSignatureAuthnPolicy for governance in the future,
   * and perhaps as a generic authentication method as well.
   */
  class MemberCOSESign1AuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;
    std::optional<std::string> gov_msg_type = std::nullopt;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_cose_sign1";

    MemberCOSESign1AuthnPolicy(
      std::optional<std::string> gov_msg_type_ = std::nullopt);
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

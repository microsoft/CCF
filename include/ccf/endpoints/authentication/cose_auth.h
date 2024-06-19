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
    std::string kid;
  };

  struct GovernanceProtectedHeader : ProtectedHeader
  {
    std::optional<std::string> gov_msg_type;
    std::optional<std::string> gov_msg_proposal_id;
    uint64_t gov_msg_created_at;
  };

  struct TimestampedProtectedHeader : ProtectedHeader
  {
    std::optional<std::string> msg_type;
    std::optional<uint64_t> msg_created_at;
  };

  struct COSESign1AuthnIdentity : public AuthnIdentity
  {
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

    COSESign1AuthnIdentity(
      const std::span<const uint8_t>& content_,
      const std::span<const uint8_t>& envelope_,
      const std::span<const uint8_t>& signature_) :
      content(content_),
      envelope(envelope_),
      signature(signature_)
    {}

    COSESign1AuthnIdentity() = default;
  };

  struct MemberCOSESign1AuthnIdentity : public COSESign1AuthnIdentity
  {
    /** CCF member ID */
    MemberId member_id;

    /** Member certificate, used to sign this request, described by keyId */
    crypto::Pem member_cert;

    /** COSE Protected Header */
    GovernanceProtectedHeader protected_header;

    MemberCOSESign1AuthnIdentity(
      const std::span<const uint8_t>& content_,
      const std::span<const uint8_t>& envelope_,
      const std::span<const uint8_t>& signature_,
      const MemberId& member_id_,
      const crypto::Pem& member_cert_,
      const GovernanceProtectedHeader& protected_header_) :
      COSESign1AuthnIdentity(content_, envelope_, signature_),
      member_id(member_id_),
      member_cert(member_cert_),
      protected_header(protected_header_)
    {}
  };

  struct UserCOSESign1AuthnIdentity : public COSESign1AuthnIdentity
  {
    /** CCF user ID */
    UserId user_id;

    /** User certificate, used to sign this request, described by keyId */
    crypto::Pem user_cert;

    /** COSE Protected Header */
    TimestampedProtectedHeader protected_header;

    UserCOSESign1AuthnIdentity(
      const std::span<const uint8_t>& content_,
      const std::span<const uint8_t>& envelope_,
      const std::span<const uint8_t>& signature_,
      const UserId& user_id_,
      const crypto::Pem& user_cert_,
      const TimestampedProtectedHeader& protected_header_) :
      COSESign1AuthnIdentity(content_, envelope_, signature_),
      user_id(user_id_),
      user_cert(user_cert_),
      protected_header(protected_header_)
    {}
  };

  /** Member COSE Sign1 Authentication Policy
   *
   * Allows ccf.gov.msg.type and ccf.gov.msg.proposal_id protected header
   * entries, to specify the type of governance action, and which proposal
   * it refers to.
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

  /** Active Member COSE Sign1 Authentication Policy
   *
   * Extends MemberCOSESign1AuthPolicy, to also require that the signer's state
   * is Active
   */
  class ActiveMemberCOSESign1AuthnPolicy : public MemberCOSESign1AuthnPolicy
  {
  public:
    static constexpr auto SECURITY_SCHEME_NAME = "active_member_cose_sign1";

    using MemberCOSESign1AuthnPolicy::MemberCOSESign1AuthnPolicy;

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<ccf::RpcContext>& ctx,
      std::string& error_reason) override;

    std::string get_security_scheme_name() override
    {
      return SECURITY_SCHEME_NAME;
    }
  };

  /** User COSE Sign1 Authentication Policy
   */
  class UserCOSESign1AuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "user_cose_sign1";

    UserCOSESign1AuthnPolicy();
    ~UserCOSESign1AuthnPolicy();

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

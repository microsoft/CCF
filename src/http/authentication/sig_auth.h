// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
#include "ds/lru.h"
#include "http/http_sig.h"

namespace ccf
{
  namespace
  {
    static std::optional<SignedReq> parse_signed_request(
      const std::shared_ptr<enclave::RpcContext>& ctx)
    {
      return http::HttpSignatureVerifier::parse(
        ctx->get_request_verb().c_str(),
        ctx->get_request_url(),
        ctx->get_request_headers(),
        ctx->get_request_body());
    }
  }

  struct UserSignatureAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID */
    UserId user_id;
    /** User certificate, used to sign this request, described by keyId */
    crypto::Pem user_cert;
    /** Canonicalised request and associated signature */
    SignedReq signed_request;
  };

  struct VerifierCache
  {
    static constexpr size_t DEFAULT_MAX_VERIFIERS = 50;

    std::mutex verifiers_lock;
    LRU<crypto::Pem, crypto::VerifierPtr> verifiers;

    VerifierCache(size_t max_verifiers = DEFAULT_MAX_VERIFIERS) :
      verifiers(max_verifiers)
    {}

    crypto::VerifierPtr get_verifier(const crypto::Pem& pem)
    {
      std::lock_guard<std::mutex> guard(verifiers_lock);

      crypto::VerifierPtr verifier = nullptr;

      auto it = verifiers.find(pem);
      if (it == verifiers.end())
      {
        it = verifiers.insert(pem, crypto::make_verifier(pem));
      }

      return it->second;
    }
  };

  class UserSignatureAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;
    VerifierCache verifiers;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "user_signature";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto signed_request = parse_signed_request(ctx);
      if (signed_request.has_value())
      {
        UserCerts users_certs_table(Tables::USER_CERTS);
        auto users_certs = tx.ro(users_certs_table);
        auto user_cert = users_certs->get(signed_request->key_id);
        if (user_cert.has_value())
        {
          auto verifier = verifiers.get_verifier(user_cert.value());
          if (verifier->verify(
                signed_request->req, signed_request->sig, signed_request->md))
          {
            auto identity = std::make_unique<UserSignatureAuthnIdentity>();
            identity->user_id = signed_request->key_id;
            identity->user_cert = user_cert.value();
            identity->signed_request = signed_request.value();
            return identity;
          }
          else
          {
            error_reason = "Signature is invalid";
          }
        }
        else
        {
          error_reason = "Signer is not a known user";
        }
      }
      else
      {
        error_reason = "Missing signature";
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx,
      std::string&& error_reason) override
    {
      ctx->set_error(
        HTTP_STATUS_UNAUTHORIZED,
        ccf::errors::InvalidAuthenticationInfo,
        std::move(error_reason));
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return security_schema;
    }
  };

  inline const OpenAPISecuritySchema UserSignatureAuthnPolicy::security_schema =
    std::make_pair(
      UserSignatureAuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "signature"},
        {"description",
         "Request must be signed according to the HTTP Signature scheme. The "
         "signer must be a user identity registered with this service."}});

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
    VerifierCache verifiers;

  public:
    static constexpr auto SECURITY_SCHEME_NAME = "member_signature";

    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto signed_request = parse_signed_request(ctx);
      if (signed_request.has_value())
      {
        MemberCerts members_certs_table(Tables::MEMBER_CERTS);
        auto member_certs = tx.ro(members_certs_table);
        auto member_cert = member_certs->get(signed_request->key_id);
        if (member_cert.has_value())
        {
          std::vector<uint8_t> digest;
          auto verifier = verifiers.get_verifier(member_cert.value());
          if (verifier->verify(
                signed_request->req,
                signed_request->sig,
                signed_request->md,
                digest))
          {
            auto identity = std::make_unique<MemberSignatureAuthnIdentity>();
            identity->member_id = signed_request->key_id;
            identity->member_cert = member_cert.value();
            identity->signed_request = signed_request.value();
            identity->request_digest = std::move(digest);
            return identity;
          }
          else
          {
            error_reason = "Signature is invalid";
          }
        }
        else
        {
          error_reason = "Signer is not a known member";
        }
      }
      else
      {
        error_reason = "Missing signature";
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx,
      std::string&& error_reason) override
    {
      ctx->set_error(
        HTTP_STATUS_UNAUTHORIZED,
        ccf::errors::InvalidAuthenticationInfo,
        std::move(error_reason));
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
    }

    std::optional<OpenAPISecuritySchema> get_openapi_security_schema()
      const override
    {
      return security_schema;
    }
  };

  inline const OpenAPISecuritySchema
    MemberSignatureAuthnPolicy::security_schema = std::make_pair(
      MemberSignatureAuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "signature"},
        {"description",
         "Request must be signed according to the HTTP Signature scheme. The "
         "signer must be a member identity registered with this service."}});
}

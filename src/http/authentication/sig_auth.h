// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
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
        ctx->get_request_path(),
        ctx->get_request_query(),
        ctx->get_request_headers(),
        ctx->get_request_body());
    }
  }

  struct UserSignatureAuthnIdentity : public AuthnIdentity
  {
    /** CCF user ID, as defined in @c public:ccf.gov.users.info table */
    UserId user_id;
    /** User certificate, used to sign this request, described by keyId */
    tls::Pem user_cert;
    /** Additional user data, as defined in @c public:ccf.gov.users.info */
    nlohmann::json user_data;
    /** Canonicalised request and associated signature */
    SignedReq signed_request;
  };

  struct VerifierCache
  {
    SpinLock verifiers_lock;
    std::unordered_map<tls::Pem, tls::VerifierPtr> verifiers;

    tls::VerifierPtr get_verifier(const tls::Pem& pem)
    {
      std::lock_guard<SpinLock> guard(verifiers_lock);

      tls::VerifierPtr verifier = nullptr;

      auto it = verifiers.find(pem);
      if (it == verifiers.end())
      {
        it = verifiers.emplace_hint(it, pem, tls::make_verifier(pem));
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
        auto digests = tx.ro<CertDigests>(Tables::USER_DIGESTS);
        auto user_id = digests->get(signed_request->key_id);

        if (user_id.has_value())
        {
          Users users_table(Tables::USERS);
          auto users = tx.ro(users_table);
          const auto user = users->get(user_id.value());
          if (!user.has_value())
          {
            throw std::logic_error("Users and user certs tables do not match");
          }

          auto verifier = verifiers.get_verifier(user->cert);
          if (verifier->verify(
                signed_request->req, signed_request->sig, signed_request->md))
          {
            auto identity = std::make_unique<UserSignatureAuthnIdentity>();
            identity->user_id = user_id.value();
            identity->user_cert = user->cert;
            identity->user_data = user->user_data;
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
    MemberId member_id;
    tls::Pem member_cert;
    nlohmann::json member_data;
    SignedReq signed_request;
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
        auto digests = tx.ro<CertDigests>(Tables::MEMBER_DIGESTS);
        auto member_id = digests->get(signed_request->key_id);

        if (member_id.has_value())
        {
          Members members_table(Tables::MEMBERS);
          auto members = tx.ro(members_table);
          const auto member = members->get(member_id.value());
          if (!member.has_value())
          {
            throw std::logic_error(
              "Members and member certs tables do not match");
          }

          std::vector<uint8_t> digest;
          auto verifier = verifiers.get_verifier(member->cert);
          if (verifier->verify(
                signed_request->req,
                signed_request->sig,
                signed_request->md,
                digest))
          {
            auto identity = std::make_unique<MemberSignatureAuthnIdentity>();
            identity->member_id = member_id.value();
            identity->member_cert = member->cert;
            identity->member_data = member->member_data;
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

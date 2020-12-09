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
    UserId user_id;
    tls::Pem user_cert;
    nlohmann::json user_data;
    SignedReq signed_request;
  };

  class UserSignatureAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;

  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto signed_request = parse_signed_request(ctx);
      if (signed_request.has_value())
      {
        auto digests_view =
          tx.get_read_only_view<CertDigests>(Tables::USER_DIGESTS);
        auto user_id = digests_view->get(signed_request->key_id);

        // TODO: This is a temporary cludge because some of our signing code
        // still doesn't set a valid keyId. This should be removed
        if (!user_id.has_value())
        {
          auto user_certs_view = tx.get_read_only_view<CertDERs>(Tables::USER_CERT_DERS);
          user_id = user_certs_view->get(ctx->session->caller_cert);
        }

        if (user_id.has_value())
        {
          Users users_table(Tables::USERS);
          auto users_view = tx.get_read_only_view(users_table);
          const auto user = users_view->get(user_id.value());
          if (!user.has_value())
          {
            throw std::logic_error("Users and user certs tables do not match");
          }

          auto identity = std::make_unique<UserSignatureAuthnIdentity>();
          identity->user_id = user_id.value();
          identity->user_cert = user->cert;
          identity->user_data = user->user_data;
          identity->signed_request = signed_request.value();
          return identity;
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
      ctx->set_response_status(HTTP_STATUS_UNAUTHORIZED);
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
      ctx->set_response_body(std::move(error_reason));
    }

    const OpenAPISecuritySchema& get_openapi_security_schema() const override
    {
      return security_schema;
    }
  };

  inline const AuthnPolicy::OpenAPISecuritySchema
    UserSignatureAuthnPolicy::security_schema = std::make_pair(
      "user_signature",
      nlohmann::json{{"type", "http"}, {"scheme", "signature"}});

  struct MemberSignatureAuthnIdentity : public AuthnIdentity
  {
    MemberId member_id;
    tls::Pem member_cert;
    nlohmann::json member_data;
    SignedReq signed_request;
  };

  class MemberSignatureAuthnPolicy : public AuthnPolicy
  {
  protected:
    static const OpenAPISecuritySchema security_schema;

  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx,
      std::string& error_reason) override
    {
      const auto signed_request = parse_signed_request(ctx);
      if (signed_request.has_value())
      {
        auto digests_view =
          tx.get_read_only_view<CertDigests>(Tables::MEMBER_DIGESTS);
        auto member_id = digests_view->get(signed_request->key_id);
        
        // TODO: This is a temporary cludge because some of our signing code
        // still doesn't set a valid keyId. This should be removed
        if (!member_id.has_value())
        {
          auto member_certs_view = tx.get_read_only_view<CertDERs>(Tables::MEMBER_CERT_DERS);
          member_id = member_certs_view->get(ctx->session->caller_cert);
        }

        if (member_id.has_value())
        {
          Members members_table(Tables::MEMBERS);
          auto members_view = tx.get_read_only_view(members_table);
          const auto member = members_view->get(member_id.value());
          if (!member.has_value())
          {
            throw std::logic_error(
              "Members and member certs tables do not match");
          }

          auto identity = std::make_unique<MemberSignatureAuthnIdentity>();
          identity->member_id = member_id.value();
          identity->member_cert = member->cert;
          identity->member_data = member->member_data;
          identity->signed_request = signed_request.value();
          return identity;
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
      ctx->set_response_status(HTTP_STATUS_UNAUTHORIZED);
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
      ctx->set_response_body(std::move(error_reason));
    }

    const OpenAPISecuritySchema& get_openapi_security_schema() const override
    {
      return security_schema;
    }
  };

  inline const AuthnPolicy::OpenAPISecuritySchema
    MemberSignatureAuthnPolicy::security_schema = std::make_pair(
      "member_signature",
      nlohmann::json{{"type", "http"}, {"scheme", "signature"}});
}

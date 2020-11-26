// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"

namespace ccf
{
  // TODO: Does this need to be distinct from UserCert..., if the data it
  // contains (that an endpoint could use) is identical?
  struct UserSignatureAuthnIdentity : public AuthnIdentity
  {
    UserId user_id;
    tls::Pem user_cert;
    nlohmann::json user_data;
  };

  class UserSignatureAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      const auto signed_request = ctx->get_signed_request();
      if (signed_request.has_value())
      {
        auto digests_view =
          tx.get_read_only_view<CertDigests>(Tables::USER_DIGESTS);
        auto user_id = digests_view->get(signed_request->key_id);
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
          return identity;
        }
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      ctx->set_response_status(HTTP_STATUS_UNAUTHORIZED);
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
      ctx->set_response_body("Request must be signed by user");
    }

    OpenAPISecuritySchema get_openapi_security_schema() const override
    {
      auto schema = nlohmann::json::object();
      schema["type"] = "http";
      schema["scheme"] = "basic"; // TODO: Inaccurate
      return std::make_pair("user_signature", schema);
    }
  };

  struct MemberSignatureAuthnIdentity : public AuthnIdentity
  {
    MemberId member_id;
    tls::Pem member_cert;
    nlohmann::json member_data;
  };

  class MemberSignatureAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      const auto signed_request = ctx->get_signed_request();
      if (signed_request.has_value())
      {
        LOG_INFO_FMT("XXXX: Yeah, that's signed");
        auto digests_view =
          tx.get_read_only_view<CertDigests>(Tables::MEMBER_DIGESTS);
        auto member_id = digests_view->get(signed_request->key_id);
        if (member_id.has_value())
        {
          LOG_INFO_FMT("XXXX: I know that member");
          Members members_table(Tables::MEMBERS);
          auto members_view = tx.get_read_only_view(members_table);
          const auto member = members_view->get(member_id.value());
          if (!member.has_value())
          {
            throw std::logic_error(
              "Members and member certs tables do not match");
          }

          LOG_INFO_FMT("XXXX: AAAAA");
          auto identity = std::make_unique<MemberSignatureAuthnIdentity>();
          identity->member_id = member_id.value();
          LOG_INFO_FMT("XXXX: BBBB");
          identity->member_cert = member->cert;
          LOG_INFO_FMT("XXXX: CCCC");
          identity->member_data = member->member_data;
          return identity;
        }
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      ctx->set_response_status(HTTP_STATUS_UNAUTHORIZED);
      ctx->set_response_header(
        http::headers::WWW_AUTHENTICATE,
        fmt::format(
          "Signature realm=\"Signed request access\", "
          "headers=\"{}\"",
          fmt::join(http::required_signature_headers, " ")));
      ctx->set_response_body("Request must be signed by member");
    }

    OpenAPISecuritySchema get_openapi_security_schema() const override
    {
      auto schema = nlohmann::json::object();
      schema["type"] = "http";
      schema["scheme"] = "basic"; // TODO: Inaccurate
      return std::make_pair("member_signature", schema);
    }
  };
}

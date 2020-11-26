// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "authentication_types.h"
#include "node/certs.h"
#include "node/members.h"
#include "node/users.h"
#include "tls/pem.h"

namespace ccf
{
  struct UserCertAuthnIdentity : public AuthnIdentity
  {
    UserId user_id;
    tls::Pem user_cert;
    nlohmann::json user_data;
  };

  class UserCertAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      const auto caller_cert = ctx->session->caller_cert;

      CertDERs users_by_cert(Tables::USER_CERT_DERS);
      auto by_certs_view = tx.get_read_only_view(users_by_cert);
      const auto user_id = by_certs_view->get(caller_cert);

      if (user_id.has_value())
      {
        Users users_table(Tables::USERS);
        auto users_view = tx.get_read_only_view(users_table);
        const auto user = users_view->get(user_id.value());
        if (!user.has_value())
        {
          throw std::logic_error("Users and user certs tables do not match");
        }

        auto identity = std::make_unique<UserCertAuthnIdentity>();
        identity->user_id = user_id.value();
        identity->user_cert = user->cert;
        identity->user_data = user->user_data;
        return identity;
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
      ctx->set_response_body("Could not find matching user certificate");
    }

    OpenAPISecuritySchema get_openapi_security_schema() const override
    {
      // TODO: There's no OpenAPI-compliant way to describe this cert auth?
      return unauthenticated_schema();
    }
  };

  struct MemberCertAuthnIdentity : public AuthnIdentity
  {
    MemberId member_id;
    tls::Pem member_cert;
    nlohmann::json member_data;
  };

  class MemberCertAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      const auto caller_cert = ctx->session->caller_cert;

      CertDERs members_by_cert(Tables::MEMBER_CERT_DERS);
      auto by_certs_view = tx.get_read_only_view(members_by_cert);
      const auto member_id = by_certs_view->get(caller_cert);

      if (member_id.has_value())
      {
        Members members_table(Tables::MEMBERS);
        auto members_view = tx.get_read_only_view(members_table);
        const auto member = members_view->get(member_id.value());
        if (!member.has_value())
        {
          throw std::logic_error("Members and member certs tables do not match");
        }

        auto identity = std::make_unique<MemberCertAuthnIdentity>();
        identity->member_id = member_id.value();
        identity->member_cert = member->cert;
        identity->member_data = member->member_data;
        return identity;
      }

      return nullptr;
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& ctx) override
    {
      ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
      ctx->set_response_body("Could not find matching member certificate");
    }

    OpenAPISecuritySchema get_openapi_security_schema() const override
    {
      // TODO: There's no OpenAPI-compliant way to describe this cert auth?
      return unauthenticated_schema();
    }
  };

  // struct MemberCertAuthnIdentity : public AuthnIdentity
  // {
  //   MemberId member_id;
  //   tls::Pem member_cert;
  //   nlohmann::json member_data;
  // };

  // class MemberCertAuthnPolicy : public AuthnPolicy
  // {
  // public:
  //   std::unique_ptr<AuthnIdentity> authenticate(
  //     kv::ReadOnlyTx& tx,
  //     const std::shared_ptr<enclave::RpcContext>& ctx) override
  //   {
  //     const auto caller_cert = ctx->session->caller_cert;

  //     CertDERs members_by_cert(Tables::MEMBER_CERT_DERS);
  //     auto by_certs_view = tx.get_read_only_view(members_by_cert);
  //     const auto member_id = by_certs_view->get(caller_cert);

  //     if (member_id.has_value())
  //     {
  //       Members members_table(Tables::MEMBERS);
  //       auto members_view = tx.get_read_only_view(members_table);
  //       const auto member = members_view->get(member_id.value());
  //       if (!member.has_value())
  //       {
  //         throw std::logic_error("Members and member certs tables do not match");
  //       }

  //       auto identity = std::make_unique<MemberCertAuthnIdentity>();
  //       identity->member_id = member_id.value();
  //       identity->member_cert = member->cert;
  //       identity->member_data = member->member_data;
  //       return identity;
  //     }

  //     return nullptr;
  //   }

  //   void set_unauthenticated_error(
  //     std::shared_ptr<enclave::RpcContext>& ctx) override
  //   {
  //     ctx->set_response_status(HTTP_STATUS_FORBIDDEN);
  //     ctx->set_response_body("Could not find matching member certificate");
  //   }

  //   OpenAPISecuritySchema get_openapi_security_schema() const override
  //   {
  //     // TODO: There's no OpenAPI-compliant way to describe this cert auth?
  //     return unauthenticated_schema();
  //   }
  // };
}

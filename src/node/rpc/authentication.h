// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "enclave/rpc_context.h"
#include "kv/tx.h"
#include "node/certs.h"
#include "node/users.h"
#include "tls/pem.h"

#include <memory>

namespace ccf
{
  struct AuthnIdentity
  {
    virtual ~AuthnIdentity() = default;
  };

  class AuthnPolicy
  {
  public:
    using OpenAPISecuritySchema = std::pair<std::string, nlohmann::json>;
    static OpenAPISecuritySchema unauthenticated_schema()
    {
      return std::make_pair("", nlohmann::json());
    }

    virtual ~AuthnPolicy() = default;

    virtual std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx& tx,
      const std::shared_ptr<enclave::RpcContext>& request) = 0;

    virtual void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>& request) = 0;

    virtual OpenAPISecuritySchema get_openapi_security_schema() const = 0;
  };

  // To make authentication _optional_, we list no-auth as one of several
  // specified policies
  // TODO: Is this worth doing? Or should we just keep "require_client_identity
  // = false", and use that for all the special casing?
  struct EmptyAuthnIdentity : public AuthnIdentity
  {};

  class EmptyAuthnPolicy : public AuthnPolicy
  {
  public:
    std::unique_ptr<AuthnIdentity> authenticate(
      kv::ReadOnlyTx&,
      const std::shared_ptr<enclave::RpcContext>&) override
    {
      return std::make_unique<EmptyAuthnIdentity>();
    }

    void set_unauthenticated_error(
      std::shared_ptr<enclave::RpcContext>&) override
    {
      throw std::logic_error("Should not happen");
    }

    OpenAPISecuritySchema get_openapi_security_schema() const override
    {
      return unauthenticated_schema();
    }
  };

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
      const auto user_id_opt = by_certs_view->get(caller_cert);

      if (user_id_opt.has_value())
      {
        Users users_table(Tables::USERS);
        auto users_view = tx.get_read_only_view(users_table);
        const auto user = users_view->get(user_id_opt.value());
        if (!user.has_value())
        {
          throw std::logic_error("Users and user certs table do not match");
        }

        auto identity = std::make_unique<UserCertAuthnIdentity>();
        identity->user_id = user_id_opt.value();
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

  // TODO: MemberCertAuthnPolicy, and NodeCertAuthnPolicy?

  // struct JwtAuthnIdentity : public AuthnIdentity
  // {
  //   JwtVerifier::Token jwt;
  // };

  // class JwtAuthnPolicy : public AuthnPolicy
  // {
  // public:
  //   std::unique_ptr<AuthnIdentity> authenticate(
  //     ReadOnlyTx& tx,
  //     const std::shared_ptr<enclave::RpcContext>& request) override
  //   {
  //     const auto jwt = JwtVerifier::extract_token(...);
  //     if (jwt.has_value())
  //     {
  //       return std::make_unique<JwtAuthnIdentity>(jwt.value());
  //     }

  //     return nullptr;
  //   }

  //   virtual void set_unauthenticated_error(
  //     std::shared_ptr<enclave::RpcContext>& request) override
  //   {
  //     request->set_response_status_code(HTTP_UNAUTHORIZED);
  //     request->set_response_header(www_authenticate, "Bearer", etc);
  //   }
  // };
}

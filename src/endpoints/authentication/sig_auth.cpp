// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/sig_auth.h"

#include "ccf/crypto/verifier.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/users.h"
#include "ds/lru.h"
#include "http/http_sig.h"

namespace ccf
{
  static std::optional<SignedReq> parse_signed_request(
    const std::shared_ptr<ccf::RpcContext>& ctx)
  {
    return http::HttpSignatureVerifier::parse(
      ctx->get_request_verb().c_str(),
      ctx->get_request_url(),
      ctx->get_request_headers(),
      ctx->get_request_body());
  }

  struct VerifierCache
  {
    static constexpr size_t DEFAULT_MAX_VERIFIERS = 50;

    ccf::pal::Mutex verifiers_lock;
    LRU<crypto::Pem, crypto::VerifierPtr> verifiers;

    VerifierCache(size_t max_verifiers = DEFAULT_MAX_VERIFIERS) :
      verifiers(max_verifiers)
    {}

    crypto::VerifierPtr get_verifier(const crypto::Pem& pem)
    {
      std::lock_guard<ccf::pal::Mutex> guard(verifiers_lock);

      auto it = verifiers.find(pem);
      if (it == verifiers.end())
      {
        it = verifiers.insert(pem, crypto::make_verifier(pem));
      }

      return it->second;
    }
  };

  UserSignatureAuthnPolicy::UserSignatureAuthnPolicy() :
    verifiers(std::make_unique<VerifierCache>())
  {}

  UserSignatureAuthnPolicy::~UserSignatureAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> UserSignatureAuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    std::optional<SignedReq> signed_request = std::nullopt;

    try
    {
      signed_request = parse_signed_request(ctx);
    }
    catch (const std::exception& e)
    {
      error_reason = e.what();
      return nullptr;
    }

    if (signed_request.has_value())
    {
      UserCerts users_certs_table(Tables::USER_CERTS);
      auto users_certs = tx.ro(users_certs_table);
      auto user_cert = users_certs->get(signed_request->key_id);
      if (user_cert.has_value())
      {
        auto verifier = verifiers->get_verifier(user_cert.value());
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

  void UserSignatureAuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
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

  const OpenAPISecuritySchema UserSignatureAuthnPolicy::security_schema =
    std::make_pair(
      UserSignatureAuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "signature"},
        {"description",
         "Request must be signed according to the HTTP Signature scheme. The "
         "signer must be a user identity registered with this service."}});

  MemberSignatureAuthnPolicy::MemberSignatureAuthnPolicy() :
    verifiers(std::make_unique<VerifierCache>())
  {}

  MemberSignatureAuthnPolicy::~MemberSignatureAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> MemberSignatureAuthnPolicy::authenticate(
    kv::ReadOnlyTx& tx,
    const std::shared_ptr<ccf::RpcContext>& ctx,
    std::string& error_reason)
  {
    std::optional<SignedReq> signed_request = std::nullopt;

    try
    {
      signed_request = parse_signed_request(ctx);
    }
    catch (const std::exception& e)
    {
      error_reason = e.what();
      return nullptr;
    }

    if (signed_request.has_value())
    {
      MemberCerts members_certs_table(Tables::MEMBER_CERTS);
      auto member_certs = tx.ro(members_certs_table);
      auto member_cert = member_certs->get(signed_request->key_id);
      if (member_cert.has_value())
      {
        std::vector<uint8_t> digest;
        auto verifier = verifiers->get_verifier(member_cert.value());
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

  void MemberSignatureAuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
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

  const OpenAPISecuritySchema MemberSignatureAuthnPolicy::security_schema =
    std::make_pair(
      MemberSignatureAuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "signature"},
        {"description",
         "Request must be signed according to the HTTP Signature scheme. The "
         "signer must be a member identity registered with this service."}});
}

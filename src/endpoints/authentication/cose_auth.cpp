// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/endpoints/authentication/cose_auth.h"

#include "ccf/crypto/verifier.h"
#include "ccf/pal/locking.h"
#include "ccf/rpc_context.h"
#include "ccf/service/tables/members.h"
#include "ccf/service/tables/users.h"
#include "ds/lru.h"
#include "http/http_sig.h"

namespace ccf
{
  MemberCOSESign1AuthnPolicy::MemberCOSESign1AuthnPolicy() = default;
  MemberSignatureAuthnPolicy::~MemberSignatureAuthnPolicy() = default;

  std::unique_ptr<AuthnIdentity> MemberCOSESign1AuthnPolicy::authenticate(
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

  void MemberCOSESign1AuthnPolicy::set_unauthenticated_error(
    std::shared_ptr<ccf::RpcContext> ctx, std::string&& error_reason)
  {
    ctx->set_error(
      HTTP_STATUS_UNAUTHORIZED,
      ccf::errors::InvalidAuthenticationInfo,
      std::move(error_reason));
    ctx->set_response_header(
      http::headers::WWW_AUTHENTICATE, "COSE-SIGN1 realm=\"Signed request access\"");
  }

  const OpenAPISecuritySchema MemberCOSESign1AuthnPolicy::security_schema =
    std::make_pair(
      MemberCOSESign1AuthnPolicy::SECURITY_SCHEME_NAME,
      nlohmann::json{
        {"type", "http"},
        {"scheme", "cose_sign1"},
        {"description",
         "Request payload must be a COSE Sign1 document, with expected protected headers."
         "Signer must be a member identity registered with this service."}});
}

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
    if (true)
    {
      /*
      MemberCerts members_certs_table(Tables::MEMBER_CERTS);
      auto member_certs = tx.ro(members_certs_table);
      auto member_cert = member_certs->get(KID);
      if (member_cert.has_value())
      {
        // Verify
      }
      */
      auto identity = std::make_unique<MemberCOSESign1AuthnPolicy>();
      return identity;
    }

    error_reason = "Did not validate";
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

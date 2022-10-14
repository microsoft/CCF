// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/endpoints/authentication/cert_auth.h"
#include "ccf/endpoints/authentication/cose_auth.h"
#include "ccf/endpoints/authentication/empty_auth.h"
#include "ccf/endpoints/authentication/jwt_auth.h"
#include "ccf/endpoints/authentication/sig_auth.h"

#include <memory>

/**
 * Defines static instances of common framework-provided authentication
 * policies, to be used freely by other apps.
 */

namespace ccf
{
  // Auth policies
  /** Perform no authentication */
  static std::shared_ptr<EmptyAuthnPolicy> empty_auth_policy =
    std::make_shared<EmptyAuthnPolicy>();

  /** Authenticate using TLS session identity, and @c public:ccf.gov.users.certs
   * table */
  static std::shared_ptr<UserCertAuthnPolicy> user_cert_auth_policy =
    std::make_shared<UserCertAuthnPolicy>();

  /** Authenticate using HTTP request signature, and
   * @c public:ccf.gov.users.certs table */
  static std::shared_ptr<UserSignatureAuthnPolicy> user_signature_auth_policy =
    std::make_shared<UserSignatureAuthnPolicy>();

  /** Authenticate using TLS session identity, and
   * @c public:ccf.gov.members.certs table */
  static std::shared_ptr<MemberCertAuthnPolicy> member_cert_auth_policy =
    std::make_shared<MemberCertAuthnPolicy>();

  /** Authenticate using HTTP request signature, and
   * @c public:ccf.gov.members.certs table */
  static std::shared_ptr<MemberSignatureAuthnPolicy>
    member_signature_auth_policy =
      std::make_shared<MemberSignatureAuthnPolicy>();

  /** Authenticate using JWT, validating the token using the
   * @c public:ccf.gov.jwt.public_signing_key_issuer and
   * @c public:ccf.gov.jwt.public_signing_keys tables */
  static std::shared_ptr<JwtAuthnPolicy> jwt_auth_policy =
    std::make_shared<JwtAuthnPolicy>();

  /** Authenticate using COSE Sign1 payloads, and
   * @c public:ccf.gov.members.certs table */
  static std::shared_ptr<MemberCOSESign1AuthnPolicy>
    member_cose_sign1_auth_policy =
      std::make_shared<MemberCOSESign1AuthnPolicy>();

  /** A clear name for the empty auth policy, to reduce errors where it is
   * accidentally defaulted or unspecified.
   */
  static AuthnPolicies no_auth_required = {};
}
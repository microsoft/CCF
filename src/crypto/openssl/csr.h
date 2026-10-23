// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/csr.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/pem.h"
#include "ccf/crypto/san.h"

#include <openssl/evp.h>
#include <optional>
#include <string>
#include <vector>

namespace ccf::crypto::OpenSSL
{
  /**
   * PKCS#10 request for public_key (a SubjectPublicKeyInfo PEM), or for the
   * signing key's own public key when absent, signed with signing_key. The
   * subject name is "K=V,K=V" text. md is the digest of the request
   * signature; algorithms that sign the message directly, such as ML-DSA,
   * pass nullptr.
   */
  Unique_X509_REQ make_csr(
    EVP_PKEY* signing_key,
    const EVP_MD* md,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::optional<Pem>& public_key);

  /**
   * X.509 v3 certificate for signing_request, signed with signing_key and
   * md (nullptr for algorithms that sign the message directly). With an
   * issuer certificate the result is issued under that certificate's
   * subject; without one it is self-signed by the request's subject. The
   * request signature is verified with the key of the party named by signer
   * before anything is issued. The certificate carries a random serial,
   * basic constraints, subject and authority key identifiers, key usage
   * keyCertSign and digitalSignature when ca is set, and the subject
   * alternative names of the request. Times are "YYYYMMDDHHMMSSZ" strings;
   * a validity period that does not end after it starts throws
   * std::logic_error.
   */
  Pem sign_csr(
    EVP_PKEY* signing_key,
    const EVP_MD* md,
    const std::optional<Pem>& issuer_cert,
    const Pem& signing_request,
    const std::string& valid_from,
    const std::string& valid_to,
    bool ca,
    CSRSigner signer);
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_verifier.h"

#include "ccf/crypto/public_key.h"
#include "ccf/ds/logger.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "x509_time.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace crypto
{
  using namespace OpenSSL;

  COSEVerifier_OpenSSL::COSEVerifier_OpenSSL(const std::vector<uint8_t>& c) :
    Verifier_OpenSSL(c)
  {}

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() {}

  bool COSEVerifier_OpenSSL::verify(const q_useful_buf_c& buf) const
  {
    return false;
  }
}

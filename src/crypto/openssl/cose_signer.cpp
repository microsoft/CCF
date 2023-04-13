// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_signer.h"

#include "ccf/crypto/public_key.h"
#include "ccf/ds/logger.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "x509_time.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <t_cose/t_cose_sign1_sign.h>

namespace crypto
{
  using namespace OpenSSL;

  COSESigner_OpenSSL::COSESigner_OpenSSL(const Pem& priv_key_pem)
  {
    kp = std::make_shared<KeyPair_OpenSSL>(priv_key_pem);
  }

  COSESigner_OpenSSL::~COSESigner_OpenSSL() = default;

  std::vector<uint8_t> COSESigner_OpenSSL::sign(
    const std::span<const uint8_t>& payload) const
  {
    t_cose_key key;
    EVP_PKEY* key_ptr = *kp;
    key.k.key_ptr = key_ptr;
    key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;

    struct t_cose_sign1_sign_ctx   sign_ctx;
    // TODO: derive algorithm from key
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, key,  NULL_Q_USEFUL_BUF_C);
    // TODO: how do custom headers work here?
    // auto rc = t_cose_sign1_sign(&sign_ctx, payload, signed_cose_buffer, &signed_cose);

    // if (rc != 0)
    // {
    //   throw std::logic_error("Failed to sign COSE payload");
    // }

    return {};
  }

  COSESignerUniquePtr make_cose_signer(const Pem& priv_key_pem)
  {
    return std::make_unique<COSESigner_OpenSSL>(priv_key_pem);
  }
}

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
#include <t_cose/t_cose_sign1_verify.h>

namespace crypto
{
  using namespace OpenSSL;

  COSEVerifier_OpenSSL::COSEVerifier_OpenSSL(
    const std::vector<uint8_t>& certificate)
  {
    Unique_BIO certbio(certificate);
    OpenSSL::Unique_X509 cert;
    if (!(cert = Unique_X509(certbio, true)))
    {
      BIO_reset(certbio);
      if (!(cert = Unique_X509(certbio, false)))
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", OpenSSL::error_string(ERR_get_error())));
      }
    }

    int mdnid, pknid, secbits;
    X509_get_signature_info(cert, &mdnid, &pknid, &secbits, 0);

    EVP_PKEY* pk = X509_get_pubkey(cert);

    if (EVP_PKEY_get0_EC_KEY(pk))
    {
      public_key = std::make_shared<PublicKey_OpenSSL>(pk);
    }
    else
    {
      throw std::logic_error("unsupported public key type");
    }
  }

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() {}

  bool COSEVerifier_OpenSSL::verify(const q_useful_buf_c& buf) const
  {
    EVP_PKEY* evp_key = *public_key;

    t_cose_key cose_key;
    cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    cose_key.k.key_ptr = evp_key;

    t_cose_sign1_verify_ctx verify_ctx;
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

    q_useful_buf_c returned_payload;
    t_cose_err_t error =
      t_cose_sign1_verify(&verify_ctx, buf, &returned_payload, nullptr);
    return error;
  }
}

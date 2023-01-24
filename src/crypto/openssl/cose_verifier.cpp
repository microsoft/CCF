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

  COSEVerifier_OpenSSL::COSEVerifier_OpenSSL(const RSAPublicKeyPtr& pubk_ptr)
  {
    public_key =
      std::make_shared<PublicKey_OpenSSL>(pubk_ptr->public_key_pem());
    // if (EVP_PKEY_get0_EC_KEY(pk))
    // {
    //   public_key = std::make_shared<PublicKey_OpenSSL>(pk);
    // }
    // else
    // {
    //   throw std::logic_error("unsupported public key type");
    // }
  }

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() = default;

  bool COSEVerifier_OpenSSL::verify(
    const std::span<const uint8_t>& buf,
    std::span<uint8_t>& authned_content) const
  {
    EVP_PKEY* evp_key = *public_key;

    t_cose_key cose_key;
    cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    cose_key.k.key_ptr = evp_key;

    t_cose_sign1_verify_ctx verify_ctx;
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, cose_key);

    q_useful_buf_c buf_;
    buf_.ptr = buf.data();
    buf_.len = buf.size();

    q_useful_buf_c authned_content_;

    t_cose_err_t error =
      t_cose_sign1_verify(&verify_ctx, buf_, &authned_content_, nullptr);
    if (error == T_COSE_SUCCESS)
    {
      authned_content = {(uint8_t*)authned_content_.ptr, authned_content_.len};
      return true;
    }
    LOG_DEBUG_FMT("COSE Sign1 verification failed with error {}", error);
    return false;
  }

  COSEVerifierUniquePtr make_cose_verifier(const std::vector<uint8_t>& cert)
  {
    return std::make_unique<COSEVerifier_OpenSSL>(cert);
  }

  COSEVerifierUniquePtr make_cose_verifier(const RSAPublicKeyPtr& pubk_ptr)
  {
    return std::make_unique<COSEVerifier_OpenSSL>(pubk_ptr);
  }
}

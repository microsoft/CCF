// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "verifier.h"

#include "public_key.h"
#include "rsa_key_pair.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace crypto
{
  using namespace OpenSSL;

  MDType Verifier_OpenSSL::get_md_type(int mdt) const
  {
    switch (mdt)
    {
      case NID_undef:
        return MDType::NONE;
      case NID_sha1:
        return MDType::SHA1;
      case NID_sha256:
        return MDType::SHA256;
      case NID_sha384:
        return MDType::SHA384;
      case NID_sha512:
        return MDType::SHA512;
      default:
        return MDType::NONE;
    }
    return MDType::NONE;
  }

  Verifier_OpenSSL::Verifier_OpenSSL(const std::vector<uint8_t>& c) : Verifier()
  {
    Unique_BIO certbio(c.data(), c.size());
    if (!(cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
    {
      BIO_reset(certbio);
      if (!(cert = d2i_X509_bio(certbio, NULL)))
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", OpenSSL::error_string(ERR_get_error())));
      }
    }

    int mdnid, pknid, secbits;
    X509_get_signature_info(cert, &mdnid, &pknid, &secbits, 0);
    md_type = get_md_type(mdnid);

    EVP_PKEY* pk = X509_get_pubkey(cert);

    if (EVP_PKEY_get0_EC_KEY(pk))
    {
      public_key = std::make_unique<PublicKey_OpenSSL>(pk);
    }
    else if (EVP_PKEY_get0_RSA(pk))
    {
      public_key = std::make_unique<RSAPublicKey_OpenSSL>(pk);
    }
    else
    {
      throw std::logic_error("unsupported public key type");
    }
  }

  Verifier_OpenSSL::~Verifier_OpenSSL()
  {
    if (cert)
      X509_free(cert);
  }

  std::vector<uint8_t> Verifier_OpenSSL::cert_der()
  {
    Unique_BIO mem;
    CHECK1(i2d_X509_bio(mem, cert));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    return {(uint8_t*)bptr->data, (uint8_t*)bptr->data + bptr->length};
  }

  Pem Verifier_OpenSSL::cert_pem()
  {
    Unique_BIO mem;
    CHECK1(PEM_write_bio_X509(mem, cert));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(mem, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
  }

  bool Verifier_OpenSSL::validate_certificate(const Pem& ca_pem)
  {
    X509* ca = nullptr;
    Unique_BIO cabio(ca_pem.data(), ca_pem.size());
    CHECKNULL(ca = PEM_read_bio_X509(cabio, NULL, 0, NULL));

    X509_STORE* store = nullptr;
    X509_STORE_CTX* store_ctx = nullptr;
    CHECKNULL(store = X509_STORE_new());
    CHECK1(X509_STORE_add_cert(store, ca));
    CHECKNULL(store_ctx = X509_STORE_CTX_new());
    CHECK1(X509_STORE_CTX_init(store_ctx, store, cert, NULL));
    auto ret = X509_verify_cert(store_ctx);
    std::cout << "VERIFY: " << ret << std::endl;

    if (ret == 0)
    {
      X509* error_cert = X509_STORE_CTX_get_current_cert(store_ctx);
      X509_NAME* certsubject = X509_NAME_new();
      certsubject = X509_get_subject_name(error_cert);
      BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
      BIO_printf(outbio, "Verification failed cert:\n");
      X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
      BIO_printf(outbio, "\n");
      X509_NAME_free(certsubject);
      BIO_free(outbio);

      std::cout << "Failed certificate: " << std::endl
                << this->cert_pem().str() << std::endl;
    }

    X509_STORE_CTX_free(store_ctx);
    X509_STORE_free(store);
    X509_free(ca);

    return ret == 1;
  }
}

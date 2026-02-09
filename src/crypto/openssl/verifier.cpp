// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/verifier.h"

#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/ec_public_key.h"
#include "crypto/openssl/rsa_public_key.h"
#include "ds/internal_logger.h"
#include "x509_time.h"

#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

namespace ccf::crypto
{
  using namespace OpenSSL;

  MDType Verifier_OpenSSL::get_md_type(int mdt)
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

  Verifier_OpenSSL::Verifier_OpenSSL(const std::vector<uint8_t>& c)
  {
    Unique_BIO certbio(c);
    cert = Unique_X509(certbio, true);
    if (cert == nullptr)
    {
      BIO_reset(certbio);
      cert = Unique_X509(certbio, false);
      if (cert == nullptr)
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", OpenSSL::error_string(ERR_get_error())));
      }
    }

    EVP_PKEY* pk = X509_get_pubkey(cert);

    auto base_id = EVP_PKEY_get_base_id(pk);
    if (base_id == EVP_PKEY_EC)
    {
      public_key = std::make_shared<ECPublicKey_OpenSSL>(pk);
    }
    else if (base_id == EVP_PKEY_RSA)
    {
      public_key = std::make_shared<RSAPublicKey_OpenSSL>(pk);
    }
    else
    {
      throw std::logic_error("unsupported public key type");
    }
  }

  Verifier_OpenSSL::~Verifier_OpenSSL() = default;

  std::vector<uint8_t> Verifier_OpenSSL::cert_der()
  {
    Unique_BIO mem;
    CHECK1(i2d_X509_bio(mem, cert));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    return {
      reinterpret_cast<uint8_t*>(bptr->data),
      reinterpret_cast<uint8_t*>(bptr->data) + bptr->length};
  }

  Pem Verifier_OpenSSL::cert_pem()
  {
    Unique_BIO mem;
    CHECK1(PEM_write_bio_X509(mem, cert));

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    return {reinterpret_cast<uint8_t*>(bptr->data), bptr->length};
  }

  bool Verifier_OpenSSL::verify_certificate(
    const std::vector<const Pem*>& trusted_certs,
    const std::vector<const Pem*>& chain,
    bool ignore_time)
  {
    Unique_X509_STORE store;
    Unique_X509_STORE_CTX store_ctx;

    for (const auto& pem : trusted_certs)
    {
      Unique_BIO tcbio(*pem);
      Unique_X509 tc(tcbio, true);
      if (tc == nullptr)
      {
        LOG_DEBUG_FMT("Failed to load certificate from PEM: {}", pem->str());
        return false;
      }

      auto rc = X509_check_ca(tc);
      // trusted certs should be a CA
      // (x509v3 basic constraints CA:TRUE or self-signed x509v1)
      // Excludes KeyUsage extensions and outdated Netscape extensions
      auto is_ca = (rc == 1 || rc == 3);
      if (!is_ca)
      {
        LOG_DEBUG_FMT("Trusted certificate is not a CA: {}", pem->str());
        return false;
      }

      CHECK1(X509_STORE_add_cert(store, tc));
    }

    Unique_STACK_OF_X509 chain_stack;
    for (const auto& pem : chain)
    {
      Unique_BIO certbio(*pem);
      Unique_X509 cert(certbio, true);
      if (cert == nullptr)
      {
        LOG_DEBUG_FMT("Failed to load certificate from PEM: {}", pem->str());
        return false;
      }

      CHECK1(sk_X509_push(chain_stack, cert));
      CHECK1(X509_up_ref(cert));
    }

    // Allow to use intermediate CAs as trust anchors
    CHECK1(X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN));

    CHECK1(X509_STORE_CTX_init(store_ctx, store, cert, chain_stack));

    if (ignore_time)
    {
      X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
      X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
      X509_VERIFY_PARAM_set_depth(param, 1);
      X509_STORE_CTX_set0_param(store_ctx, param);
    }

    auto valid = X509_verify_cert(store_ctx) == 1;
    if (!valid)
    {
      auto error = X509_STORE_CTX_get_error(store_ctx);
      const auto* msg = X509_verify_cert_error_string(error);
      LOG_DEBUG_FMT("Failed to verify certificate: {}", msg);
      LOG_DEBUG_FMT("Target: {}", cert_pem().str());
      for (const auto* pem : chain)
      {
        LOG_DEBUG_FMT("Chain: {}", pem->str());
      }
      for (const auto* pem : trusted_certs)
      {
        LOG_DEBUG_FMT("Trusted: {}", pem->str());
      }
    }
    return valid;
  }

  bool Verifier_OpenSSL::is_self_signed() const
  {
    return (X509_get_extension_flags(cert) & EXFLAG_SS) != 0U;
  }

  std::string Verifier_OpenSSL::serial_number() const
  {
    const ASN1_INTEGER* sn = X509_get0_serialNumber(cert);
    Unique_BIO mem;
    i2a_ASN1_INTEGER(mem, sn);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    return {bptr->data, bptr->length};
  }

  std::pair<std::string, std::string> Verifier_OpenSSL::validity_period() const
  {
    return std::make_pair(
      to_x509_time_string(X509_get0_notBefore(cert)),
      to_x509_time_string(X509_get0_notAfter(cert)));
  }

  std::string Verifier_OpenSSL::subject() const
  {
    X509_NAME* name = X509_get_subject_name(cert);
    Unique_BIO mem;
    X509_NAME_print_ex(mem, name, 0, 0);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(mem, &bptr);
    return {bptr->data, bptr->length};
  }

  size_t Verifier_OpenSSL::remaining_seconds(
    const ccf::ds::EpochClock::time_point& now) const
  {
    auto [from, to] = validity_period();
    auto tp_to = ccf::ds::time_point_from_string(to);
    return std::chrono::duration_cast<std::chrono::seconds>(tp_to - now)
             .count() +
      1;
  }

  double Verifier_OpenSSL::remaining_percentage(
    const ccf::ds::EpochClock::time_point& now) const
  {
    auto [from, to] = validity_period();
    auto tp_from = ccf::ds::time_point_from_string(from);
    auto tp_to = ccf::ds::time_point_from_string(to);
    auto total_sec =
      std::chrono::duration_cast<std::chrono::seconds>(tp_to - tp_from)
        .count() +
      1;
    auto rem_sec =
      std::chrono::duration_cast<std::chrono::seconds>(tp_to - now).count() + 1;
    return rem_sec / (double)total_sec;
  }
}

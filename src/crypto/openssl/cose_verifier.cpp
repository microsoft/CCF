// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_verifier.h"

#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/rsa_key_pair.h"
#include "ds/internal_logger.h"
#include "x509_time.h"

#include <crypto/cbor.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <t_cose/t_cose_sign1_verify.h>

namespace
{
  std::optional<int> extract_algorithm_from_header(
    std::span<const uint8_t> cose_msg)
  {
    using namespace ccf::cbor;

    auto cose_cbor =
      rethrow_with_msg([&]() { return parse(cose_msg); }, "Parse COSE CBOR");

    const auto& cose_envelope = rethrow_with_msg(
      [&]() -> auto& { return cose_cbor->tag_at(18); }, "Parse COSE tag");

    const auto& phdr_raw = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return parse(phdr_raw->as_bytes()); }, "Decode protected header");

    const int64_t alg = rethrow_with_msg(
      [&]() {
        return phdr->map_at(make_signed(ccf::crypto::COSE_PHEADER_KEY_ALG))
          ->as_signed();
      },
      "Retrieve alg from protected header");

    return alg;
  }

  q_useful_buf_c buf_from_span(const std::span<const uint8_t> span)
  {
    return {.ptr = span.data(), .len = span.size()};
  }

  class TCOSEVerify
  {
  private:
    EVP_PKEY* pkey = nullptr;
    t_cose_key cose_key = {};

  public:
    t_cose_sign1_verify_ctx ctx = {};

    TCOSEVerify(
      std::shared_ptr<ccf::crypto::PublicKey_OpenSSL> pkey_,
      const std::span<const uint8_t> envelope) :
      pkey(*pkey_)
    {
      const auto alg_header = extract_algorithm_from_header(envelope);
      if (!alg_header.has_value())
      {
        throw std::domain_error("COSE header is missing 'alg' parameter");
      }

      pkey_->check_is_cose_compatible(alg_header.value());

      cose_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
      cose_key.k.key_ptr = pkey;

      t_cose_sign1_verify_init(&ctx, T_COSE_OPT_TAG_REQUIRED);
      t_cose_sign1_set_verification_key(&ctx, cose_key);
    }
  };

}

namespace ccf::crypto
{
  using namespace OpenSSL;

  COSECertVerifier_OpenSSL::COSECertVerifier_OpenSSL(
    const std::vector<uint8_t>& certificate)
  {
    Unique_BIO certbio(certificate);
    OpenSSL::Unique_X509 cert;
    if ((cert = Unique_X509(certbio, true)) == nullptr)
    {
      BIO_reset(certbio);
      if ((cert = Unique_X509(certbio, false)) == nullptr)
      {
        throw std::invalid_argument(fmt::format(
          "OpenSSL error: {}", OpenSSL::error_string(ERR_get_error())));
      }
    }
    EVP_PKEY* pk = X509_get_pubkey(cert);

    public_key = std::make_shared<PublicKey_OpenSSL>(pk);
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(const Pem& public_key_)
  {
    public_key = std::make_shared<PublicKey_OpenSSL>(public_key_);
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(
    std::span<const uint8_t> public_key_der_)
  {
    public_key = std::make_shared<PublicKey_OpenSSL>(public_key_der_);
  }

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() = default;

  bool COSEVerifier_OpenSSL::verify(
    const std::span<const uint8_t>& envelope,
    std::span<uint8_t>& authned_content) const
  {
    try
    {
      TCOSEVerify cose_verify(public_key, envelope);
      q_useful_buf_c envelope_ = buf_from_span(envelope);

      q_useful_buf_c authned_content_ = {};

      t_cose_err_t error = t_cose_sign1_verify(
        &cose_verify.ctx, envelope_, &authned_content_, nullptr);
      if (error == T_COSE_SUCCESS)
      {
        authned_content = {
          reinterpret_cast<uint8_t*>(const_cast<void*>(authned_content_.ptr)),
          authned_content_.len};
        return true;
      }

      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", error);
    }
    catch (const std::exception& e)
    {
      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", e.what());
    }
    return false;
  }

  bool COSEVerifier_OpenSSL::verify_detached(
    std::span<const uint8_t> envelope, std::span<const uint8_t> payload) const
  {
    try
    {
      TCOSEVerify cose_verify(public_key, envelope);

      q_useful_buf_c envelope_ = buf_from_span(envelope);

      q_useful_buf_c payload_ = {};
      payload_.ptr = payload.data();
      payload_.len = payload.size();

      t_cose_err_t error = t_cose_sign1_verify_detached(
        &cose_verify.ctx, envelope_, NULL_Q_USEFUL_BUF_C, payload_, nullptr);

      if (error == T_COSE_SUCCESS)
      {
        return true;
      }

      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", error);
    }
    catch (const std::exception& e)
    {
      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", e.what());
    }
    return false;
  }

  COSEVerifierUniquePtr make_cose_verifier_from_cert(
    const std::vector<uint8_t>& cert)
  {
    return std::make_unique<COSECertVerifier_OpenSSL>(cert);
  }

  COSEVerifierUniquePtr make_cose_verifier_from_key(const Pem& public_key)
  {
    return std::make_unique<COSEKeyVerifier_OpenSSL>(public_key);
  }

  COSEVerifierUniquePtr make_cose_verifier_from_key(
    std::span<const uint8_t> public_key)
  {
    return std::make_unique<COSEKeyVerifier_OpenSSL>(public_key);
  }

  COSEEndorsementValidity extract_cose_endorsement_validity(
    std::span<const uint8_t> cose_msg)
  {
    using namespace ccf::cbor;

    auto cose_cbor =
      rethrow_with_msg([&]() { return parse(cose_msg); }, "Parse COSE CBOR");

    const auto& cose_envelope = rethrow_with_msg(
      [&]() -> auto& { return cose_cbor->tag_at(18); }, "Parse COSE tag");

    const auto& phdr_raw = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return parse(phdr_raw->as_bytes()); }, "Decode protected header");

    const auto& ccf_claims = rethrow_with_msg(
      [&]() -> auto& {
        return phdr->map_at(make_string(ccf::crypto::COSE_PHEADER_KEY_CCF));
      },
      "Retrieve CCF claims");

    auto from = rethrow_with_msg(
      [&]() {
        return ccf_claims->map_at(make_string(COSE_PHEADER_KEY_RANGE_BEGIN))
          ->as_string();
      },
      "Retrieve epoch range begin");

    auto to = rethrow_with_msg(
      [&]() {
        return ccf_claims->map_at(make_string(COSE_PHEADER_KEY_RANGE_END))
          ->as_string();
      },
      "Retrieve epoch range end");

    return COSEEndorsementValidity{
      .from_txid = std::string(from), .to_txid = std::string(to)};
  }
}

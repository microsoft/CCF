// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_verifier.h"

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/ec_public_key.h"
#include "crypto/openssl/rsa_public_key.h"
#include "ds/internal_logger.h"

#include <climits>
#include <crypto/cbor_tags.h>
#include <crypto/cose.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <tav/cbor.hpp>
#include <type_traits>

namespace
{
  using namespace ccf::crypto;

  // COSE ECDSA signatures are r || s, each the size of a curve coordinate
  // (32, 48 and 66 bytes for P-256, P-384 and P-521).
  size_t expected_signature_size(CurveID curve)
  {
    switch (curve)
    {
      case CurveID::SECP256R1:
        return 64;
      case CurveID::SECP384R1:
        return 96;
      case CurveID::SECP521R1:
        return 132;
      case CurveID::NONE:
      case CurveID::CURVE25519:
      case CurveID::X25519:
      default:
        throw std::logic_error(
          fmt::format("Unsupported COSE ECDSA curve {}", curve));
    }
  }

  struct AlgorithmParameters
  {
    MDType digest;
    CurveID curve;
    size_t salt_length;
  };

  AlgorithmParameters algorithm_parameters(int64_t alg)
  {
    switch (alg)
    {
      case ccf::cose::alg::ES256:
      case ccf::cose::alg::ESP256:
        return {MDType::SHA256, CurveID::SECP256R1, 0};
      case ccf::cose::alg::ES384:
      case ccf::cose::alg::ESP384:
        return {MDType::SHA384, CurveID::SECP384R1, 0};
      case ccf::cose::alg::ES512:
      case ccf::cose::alg::ESP512:
        return {MDType::SHA512, CurveID::SECP521R1, 0};
      case ccf::cose::alg::PS256:
        return {MDType::SHA256, CurveID::NONE, SHA256_DIGEST_LENGTH};
      case ccf::cose::alg::PS384:
        return {MDType::SHA384, CurveID::NONE, SHA384_DIGEST_LENGTH};
      case ccf::cose::alg::PS512:
        return {MDType::SHA512, CurveID::NONE, SHA512_DIGEST_LENGTH};
      default:
        throw std::runtime_error(
          fmt::format("Unsupported COSE signature algorithm {}", alg));
    }
  }

  using CoseSign1Components = std::tuple<
    std::span<const uint8_t>, // phdr
    std::optional<std::span<const uint8_t>>, // payload (nullopt if detached)
    std::span<const uint8_t> // sig
    >;

  CoseSign1Components decompose_cose_sign1(std::span<const uint8_t> envelope)
  {
    using namespace tav::cbor;

    auto cose_cbor = rethrow_with_msg(
      [&]() { return nondet_parse(envelope); }, "Parse COSE CBOR");

    const auto cose_envelope = rethrow_with_msg(
      [&]() { return cose_cbor.tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");

    auto phdr = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(0).as_bytes(); },
      "Parse protected header");

    std::optional<std::span<const uint8_t>> payload;
    {
      const auto& payload_item = cose_envelope.array_at(2);
      try
      {
        payload = payload_item.as_bytes();
      }
      catch (const tav::cbor::DecodeError&)
      {
        // as_bytes() fails when payload is CBOR null (detached)
        if (payload_item.as_simple() != tav::cbor::SimpleValue::Null)
        {
          throw;
        }
      }
    }

    auto sig = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(3).as_bytes(); },
      "Parse signature");

    return {phdr, payload, sig};
  }

  int64_t extract_alg(std::span<const uint8_t> phdr_bytes)
  {
    using namespace tav::cbor;
    const Value phdr = nondet_parse(phdr_bytes);
    const Value alg_key = make_signed(ccf::cose::header::iana::ALG);
    return phdr.map_at(alg_key).as_signed();
  }

  CoseKey cose_key_from_pkey(OpenSSL::Unique_PKEY key)
  {
    switch (EVP_PKEY_get_base_id(key))
    {
      case EVP_PKEY_EC:
      {
        auto ec_key = std::make_shared<ECPublicKey_OpenSSL>(std::move(key));
        // Throws for curves that COSE verification does not support.
        (void)ec_key->get_curve_id();
        return ec_key;
      }
      case EVP_PKEY_RSA:
        return std::make_shared<RSAPublicKey_OpenSSL>(std::move(key));
      default:
        throw std::runtime_error("Unsupported COSE public key type");
    }
  }

  CoseKey cose_key_from_bytes(std::span<const uint8_t> encoded, bool pem)
  {
    if (encoded.empty() || encoded.size() > INT_MAX)
    {
      throw std::runtime_error("Invalid public key size");
    }
    OpenSSL::Unique_BIO bio(encoded);
    EVP_PKEY* parsed = pem ?
      PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr) :
      d2i_PUBKEY_bio(bio, nullptr);
    if (parsed == nullptr)
    {
      throw std::runtime_error(
        fmt::format("Failed to parse public key: {}", OpenSSL::first_error()));
    }
    OpenSSL::Unique_PKEY key(parsed, EVP_PKEY_free);
    return cose_key_from_pkey(std::move(key));
  }

  enum class CertificateFormat : uint8_t
  {
    AUTO,
    PEM,
    DER
  };

  // Certificate import errors are std::invalid_argument, as in
  // Verifier_OpenSSL.
  CoseKey cose_key_from_certificate(
    std::span<const uint8_t> encoded, CertificateFormat format)
  {
    if (encoded.empty() || encoded.size() > INT_MAX)
    {
      throw std::invalid_argument("Invalid certificate size");
    }
    OpenSSL::Unique_BIO bio(encoded);
    OpenSSL::Unique_X509 cert(bio, format != CertificateFormat::DER);
    if (cert == nullptr && format == CertificateFormat::AUTO)
    {
      OpenSSL::CHECK1(BIO_reset(bio));
      cert = OpenSSL::Unique_X509(bio, false);
    }
    if (cert == nullptr)
    {
      throw std::invalid_argument(
        fmt::format("Failed to parse certificate: {}", OpenSSL::first_error()));
    }
    EVP_PKEY* public_key = X509_get_pubkey(cert);
    if (public_key == nullptr)
    {
      throw std::invalid_argument(fmt::format(
        "Failed to get certificate public key: {}", OpenSSL::first_error()));
    }
    OpenSSL::Unique_PKEY key(public_key, EVP_PKEY_free);
    try
    {
      return cose_key_from_pkey(std::move(key));
    }
    catch (const std::runtime_error& error)
    {
      throw std::invalid_argument(error.what());
    }
  }
}

namespace ccf::crypto
{
  std::unique_ptr<COSECertVerifier_OpenSSL> COSECertVerifier_OpenSSL::from_any(
    const std::vector<uint8_t>& certificate)
  {
    return std::unique_ptr<COSECertVerifier_OpenSSL>(
      new COSECertVerifier_OpenSSL(
        cose_key_from_certificate(certificate, CertificateFormat::AUTO)));
  }

  std::unique_ptr<COSECertVerifier_OpenSSL> COSECertVerifier_OpenSSL::from_pem(
    const Pem& pem)
  {
    return std::unique_ptr<COSECertVerifier_OpenSSL>(
      new COSECertVerifier_OpenSSL(
        cose_key_from_certificate(pem.raw(), CertificateFormat::PEM)));
  }

  std::unique_ptr<COSECertVerifier_OpenSSL> COSECertVerifier_OpenSSL::from_der(
    const std::vector<uint8_t>& der)
  {
    return std::unique_ptr<COSECertVerifier_OpenSSL>(
      new COSECertVerifier_OpenSSL(
        cose_key_from_certificate(der, CertificateFormat::DER)));
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(const Pem& public_key_) :
    COSEVerifier_OpenSSL(cose_key_from_bytes(public_key_.raw(), true))
  {}

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(
    std::span<const uint8_t> public_key_der_) :
    COSEVerifier_OpenSSL(cose_key_from_bytes(public_key_der_, false))
  {}

  COSEVerifier_OpenSSL::~COSEVerifier_OpenSSL() = default;

  bool COSEVerifier_OpenSSL::verify(
    const std::span<const uint8_t>& envelope,
    std::span<uint8_t>& authned_content) const
  {
    try
    {
      auto [phdr, payload, sig] = decompose_cose_sign1(envelope);

      if (!payload.has_value())
      {
        LOG_DEBUG_FMT("COSE Sign1 verification failed: payload is detached");
        return false;
      }

      if (verify_decomposed(phdr, *payload, sig, extract_alg(phdr)))
      {
        authned_content = {
          const_cast<uint8_t*>(payload->data()), payload->size()};
        return true;
      }
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
      auto [phdr, _payload, sig] = decompose_cose_sign1(envelope);

      return verify_decomposed(phdr, payload, sig, extract_alg(phdr));
    }
    catch (const std::exception& e)
    {
      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", e.what());
    }
    return false;
  }

  bool COSEVerifier_OpenSSL::verify_decomposed(
    std::span<const uint8_t> phdr,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> sig,
    int64_t alg) const
  {
    try
    {
      const auto parameters = algorithm_parameters(alg);
      const auto tbs = cose::make_cose_sign1_tbs(phdr, payload);
      const bool verified = std::visit(
        [&](const auto& key) {
          if constexpr (std::is_same_v<
                          std::remove_cvref_t<decltype(key)>,
                          RSAPublicKeyPtr>)
          {
            if (parameters.curve != CurveID::NONE)
            {
              throw std::runtime_error("COSE algorithm does not match RSA key");
            }
            return key->verify(
              tbs.data(),
              tbs.size(),
              sig.data(),
              sig.size(),
              parameters.digest,
              RSAPadding::PKCS_PSS,
              parameters.salt_length);
          }
          else
          {
            if (parameters.curve != key->get_curve_id())
            {
              throw std::runtime_error("COSE algorithm does not match EC key");
            }
            const auto signature_size =
              expected_signature_size(parameters.curve);
            if (sig.size() != signature_size)
            {
              throw std::runtime_error(fmt::format(
                "Expected {} byte COSE ECDSA signature, got {}",
                signature_size,
                sig.size()));
            }
            const auto der = ecdsa_sig_p1363_to_der(sig);
            return key->verify(
              tbs.data(),
              tbs.size(),
              der.data(),
              der.size(),
              parameters.digest);
          }
        },
        verify_key);
      if (!verified)
      {
        LOG_DEBUG_FMT("COSE Sign1 verification failed: signature mismatch");
      }
      return verified;
    }
    catch (const std::exception& e)
    {
      LOG_DEBUG_FMT("COSE Sign1 verification failed: {}", e.what());
    }
    return false;
  }

  COSEVerifierUniquePtr make_cose_verifier_any_cert(
    const std::vector<uint8_t>& cert)
  {
    return COSECertVerifier_OpenSSL::from_any(cert);
  }

  COSEVerifierUniquePtr make_cose_verifier_from_pem_cert(const Pem& pem)
  {
    return COSECertVerifier_OpenSSL::from_pem(pem);
  }

  COSEVerifierUniquePtr make_cose_verifier_from_der_cert(
    const std::vector<uint8_t>& der)
  {
    return COSECertVerifier_OpenSSL::from_der(der);
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
    using namespace tav::cbor;

    auto cose_cbor = rethrow_with_msg(
      [&]() { return nondet_parse(cose_msg); }, "Parse COSE CBOR");

    const auto cose_envelope = rethrow_with_msg(
      [&]() { return cose_cbor.tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");

    const auto phdr_raw = rethrow_with_msg(
      [&]() { return cose_envelope.array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return nondet_parse(phdr_raw.as_bytes()); },
      "Decode protected header");

    const auto ccf_claims = rethrow_with_msg(
      [&]() {
        return phdr.map_at(make_string(ccf::cose::header::custom::CCF_V1));
      },
      "Retrieve CCF claims");

    auto from = rethrow_with_msg(
      [&]() {
        return ccf_claims
          .map_at(make_string(ccf::cose::header::custom::TX_RANGE_BEGIN))
          .as_string();
      },
      "Retrieve epoch range begin");

    auto to = rethrow_with_msg(
      [&]() {
        return ccf_claims
          .map_at(make_string(ccf::cose::header::custom::TX_RANGE_END))
          .as_string();
      },
      "Retrieve epoch range end");

    return COSEEndorsementValidity{
      .from_txid = std::string(from), .to_txid = std::string(to)};
  }
}

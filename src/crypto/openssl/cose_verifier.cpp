// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_verifier.h"

#include "cose/cose_rs_ffi.h"
#include "ds/internal_logger.h"

#include <crypto/cbor.h>
#include <crypto/cose.h>

namespace
{
  using CoseSign1Components = std::tuple<
    std::span<const uint8_t>, // phdr
    std::optional<std::span<const uint8_t>>, // payload (nullopt if detached)
    std::span<const uint8_t> // sig
    >;

  CoseSign1Components decompose_cose_sign1(std::span<const uint8_t> envelope)
  {
    using namespace ccf::cbor;

    auto cose_cbor =
      rethrow_with_msg([&]() { return parse(envelope); }, "Parse COSE CBOR");

    const auto& cose_envelope = rethrow_with_msg(
      [&]() -> auto& { return cose_cbor->tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");

    auto phdr = rethrow_with_msg(
      [&]() { return cose_envelope->array_at(0)->as_bytes(); },
      "Parse protected header");

    std::optional<std::span<const uint8_t>> payload;
    {
      const auto& payload_item = cose_envelope->array_at(2);
      try
      {
        payload = payload_item->as_bytes();
      }
      catch (const CBORDecodeError&)
      {
        // as_bytes() fails when payload is CBOR null (detached)
        if (payload_item->as_simple() != ccf::cbor::SimpleValue::Null)
        {
          throw;
        }
      }
    }

    auto sig = rethrow_with_msg(
      [&]() { return cose_envelope->array_at(3)->as_bytes(); },
      "Parse signature");

    return {phdr, payload, sig};
  }

  int64_t extract_alg(std::span<const uint8_t> phdr_bytes)
  {
    using namespace ccf::cbor;
    auto phdr = parse(phdr_bytes);
    return phdr->map_at(make_signed(ccf::cose::header::iana::ALG))->as_signed();
  }
}

namespace ccf::crypto
{
  std::unique_ptr<COSECertVerifier_OpenSSL> COSECertVerifier_OpenSSL::from_any(
    const std::vector<uint8_t>& certificate)
  {
    // Try PEM first, then DER.
    CoseBuffer pem_err;
    auto key =
      CoseKey::from_pem_cert(certificate.data(), certificate.size(), pem_err);
    if (!key.is_set())
    {
      CoseBuffer der_err;
      key =
        CoseKey::from_der_cert(certificate.data(), certificate.size(), der_err);
      if (!key.is_set())
      {
        throw std::invalid_argument(fmt::format(
          "Failed to parse certificate (PEM: {}, DER: {})",
          pem_err.is_set() ? pem_err.to_string() : "unknown error",
          der_err.is_set() ? der_err.to_string() : "unknown error"));
      }
    }
    return std::unique_ptr<COSECertVerifier_OpenSSL>(
      new COSECertVerifier_OpenSSL(std::move(key)));
  }

  std::unique_ptr<COSECertVerifier_OpenSSL> COSECertVerifier_OpenSSL::from_pem(
    const Pem& pem)
  {
    CoseBuffer key_err;
    auto key = CoseKey::from_pem_cert(pem.data(), pem.size(), key_err);
    if (!key.is_set())
    {
      throw std::invalid_argument(fmt::format(
        "Failed to parse PEM certificate: {}",
        key_err.is_set() ? key_err.to_string() : "unknown error"));
    }
    return std::unique_ptr<COSECertVerifier_OpenSSL>(
      new COSECertVerifier_OpenSSL(std::move(key)));
  }

  std::unique_ptr<COSECertVerifier_OpenSSL> COSECertVerifier_OpenSSL::from_der(
    const std::vector<uint8_t>& der)
  {
    CoseBuffer key_err;
    auto key = CoseKey::from_der_cert(der.data(), der.size(), key_err);
    if (!key.is_set())
    {
      throw std::invalid_argument(fmt::format(
        "Failed to parse DER certificate: {}",
        key_err.is_set() ? key_err.to_string() : "unknown error"));
    }
    return std::unique_ptr<COSECertVerifier_OpenSSL>(
      new COSECertVerifier_OpenSSL(std::move(key)));
  }

  static CoseKey cose_key_from_pem(const Pem& pem)
  {
    CoseBuffer key_err;
    auto key = CoseKey::from_pem_public(pem.data(), pem.size(), key_err);
    if (!key.is_set())
    {
      throw std::runtime_error(fmt::format(
        "Failed to create COSE verification key: {}",
        key_err.is_set() ? key_err.to_string() : "unknown error"));
    }
    return key;
  }

  static CoseKey cose_key_from_der(std::span<const uint8_t> der)
  {
    CoseBuffer key_err;
    auto key = CoseKey::from_public(der.data(), der.size(), key_err);
    if (!key.is_set())
    {
      throw std::runtime_error(fmt::format(
        "Failed to create COSE verification key: {}",
        key_err.is_set() ? key_err.to_string() : "unknown error"));
    }
    return key;
  }

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(const Pem& public_key_) :
    COSEVerifier_OpenSSL(cose_key_from_pem(public_key_))
  {}

  COSEKeyVerifier_OpenSSL::COSEKeyVerifier_OpenSSL(
    std::span<const uint8_t> public_key_der_) :
    COSEVerifier_OpenSSL(cose_key_from_der(public_key_der_))
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

      auto alg = extract_alg(phdr);
      CoseBuffer verify_err;
      auto rc = cose_verify1(
        verify_key,
        alg,
        phdr.data(),
        phdr.size(),
        payload->data(),
        payload->size(),
        sig.data(),
        sig.size(),
        verify_err);
      if (rc == 0)
      {
        authned_content = {
          const_cast<uint8_t*>(payload->data()), payload->size()};
        return true;
      }

      LOG_DEBUG_FMT(
        "COSE Sign1 verification failed: {}",
        verify_err.is_set() ? verify_err.to_string() : "unknown error");
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

      auto alg = extract_alg(phdr);
      CoseBuffer verify_err;
      auto rc = cose_verify1(
        verify_key,
        alg,
        phdr.data(),
        phdr.size(),
        payload.data(),
        payload.size(),
        sig.data(),
        sig.size(),
        verify_err);
      if (rc == 0)
      {
        return true;
      }

      LOG_DEBUG_FMT(
        "COSE Sign1 verification failed: {}",
        verify_err.is_set() ? verify_err.to_string() : "unknown error");
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
      CoseBuffer verify_err;
      auto rc = cose_verify1(
        verify_key,
        alg,
        phdr.data(),
        phdr.size(),
        payload.data(),
        payload.size(),
        sig.data(),
        sig.size(),
        verify_err);
      if (rc == 0)
      {
        return true;
      }

      LOG_DEBUG_FMT(
        "COSE Sign1 verification failed: {}",
        verify_err.is_set() ? verify_err.to_string() : "unknown error");
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
    using namespace ccf::cbor;

    auto cose_cbor =
      rethrow_with_msg([&]() { return parse(cose_msg); }, "Parse COSE CBOR");

    const auto& cose_envelope = rethrow_with_msg(
      [&]() -> auto& { return cose_cbor->tag_at(ccf::cbor::tag::COSE_SIGN_1); },
      "Parse COSE tag");

    const auto& phdr_raw = rethrow_with_msg(
      [&]() -> auto& { return cose_envelope->array_at(0); },
      "Parse raw protected header");

    auto phdr = rethrow_with_msg(
      [&]() { return parse(phdr_raw->as_bytes()); }, "Decode protected header");

    const auto& ccf_claims = rethrow_with_msg(
      [&]() -> auto& {
        return phdr->map_at(make_string(ccf::cose::header::custom::CCF_V1));
      },
      "Retrieve CCF claims");

    auto from = rethrow_with_msg(
      [&]() {
        return ccf_claims
          ->map_at(make_string(ccf::cose::header::custom::TX_RANGE_BEGIN))
          ->as_string();
      },
      "Retrieve epoch range begin");

    auto to = rethrow_with_msg(
      [&]() {
        return ccf_claims
          ->map_at(make_string(ccf::cose::header::custom::TX_RANGE_END))
          ->as_string();
      },
      "Retrieve epoch range end");

    return COSEEndorsementValidity{
      .from_txid = std::string(from), .to_txid = std::string(to)};
  }
}

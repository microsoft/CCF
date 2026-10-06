// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/cose_signatures_config.h"
#include "ccf/crypto/cose_key.h"
#include "ccf/crypto/curve.h"
#include "ccf/crypto/verifier.h"
#include "ccf/service_signing_keys.h"
#include "crypto/certs.h"
#include "crypto/cose.h"
#include "crypto/openssl/ec_key_pair.h"

#include <fmt/format.h>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf
{
  // The CLASSICAL service signing key as a COSE_Key, whose alg is the
  // algorithm of the ledger's COSE signatures with that key
  inline std::vector<uint8_t> classical_signing_key_cbor(
    const ccf::crypto::ECPublicKeyPtr& key)
  {
    return ccf::crypto::COSEKey(key).to_cbor(
      ccf::cose::algorithm_for_curve(key->get_curve_id()).alg);
  }

  // Parses a CLASSICAL service signing key, which may be untrusted
  inline ccf::crypto::COSEKey parse_classical_signing_key(
    const std::vector<uint8_t>& cose_key)
  {
    auto key = ccf::crypto::COSEKey::from_cbor(cose_key);
    if (key.kty() != ccf::crypto::COSEKeyType::EC2)
    {
      throw std::invalid_argument(fmt::format(
        "{} service signing key is not an EC2 COSE_Key",
        SigningKeyType::CLASSICAL));
    }
    return key;
  }

  inline ServiceSigningKeys service_signing_keys_from_public_key(
    const ccf::crypto::ECPublicKeyPtr& key)
  {
    return {{SigningKeyType::CLASSICAL, classical_signing_key_cbor(key)}};
  }

  inline ServiceSigningKeys service_signing_keys_from_certificate(
    const std::vector<uint8_t>& certificate)
  {
    return service_signing_keys_from_public_key(ccf::crypto::make_ec_public_key(
      ccf::crypto::make_unique_verifier(certificate)->public_key_der()));
  }

  // Signing keys take precedence over the deprecated previous service
  // certificate, whose public key is used when no keys are configured.
  inline std::optional<ServiceSigningKeys>
  resolve_previous_service_signing_keys(
    const std::optional<ServiceSigningKeys>& keys,
    const std::optional<std::vector<uint8_t>>& certificate)
  {
    if (keys.has_value())
    {
      return keys;
    }
    if (certificate.has_value())
    {
      return service_signing_keys_from_certificate(*certificate);
    }
    return std::nullopt;
  }

  inline ccf::crypto::COSEKey get_previous_service_classical_signing_key(
    const std::optional<ServiceSigningKeys>& keys)
  {
    if (!keys.has_value())
    {
      throw std::logic_error("No previous service identity is configured");
    }
    const auto key = keys->find(SigningKeyType::CLASSICAL);
    if (key == keys->end())
    {
      throw std::logic_error(fmt::format(
        "Missing {} previous service signing public key",
        SigningKeyType::CLASSICAL));
    }
    return parse_classical_signing_key(key->second);
  }

  inline ccf::crypto::COSEKey get_previous_service_classical_signing_key(
    const std::optional<ServiceSigningKeys>& keys,
    const std::optional<std::vector<uint8_t>>& certificate)
  {
    return get_previous_service_classical_signing_key(
      resolve_previous_service_signing_keys(keys, certificate));
  }

  struct NetworkIdentity
  {
    ccf::crypto::Pem priv_key;
    ccf::crypto::Pem cert;

    bool operator==(const NetworkIdentity& other) const = default;

    NetworkIdentity(
      const std::string& subject_name,
      ccf::crypto::CurveID curve_id,
      const std::string& valid_from,
      size_t validity_period_days)
    {
      auto identity_key_pair =
        std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(curve_id);
      priv_key = identity_key_pair->private_key_pem();

      cert = ccf::crypto::create_self_signed_cert(
        identity_key_pair,
        subject_name,
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    NetworkIdentity(const NetworkIdentity& other) = default;

    NetworkIdentity() = default;

    virtual ~NetworkIdentity()
    {
      OPENSSL_cleanse(priv_key.data(), priv_key.size());
    }

    ccf::crypto::Pem renew_certificate(
      const std::string& valid_from, size_t validity_period_days)
    {
      return ccf::crypto::create_self_signed_cert(
        get_key_pair(),
        ccf::crypto::get_subject_name(cert),
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    void set_certificate(const ccf::crypto::Pem& new_cert)
    {
      cert = new_cert;
    }

    std::shared_ptr<ccf::crypto::ECKeyPair_OpenSSL> get_key_pair()
    {
      return std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(priv_key);
    }
  };
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/cose_signatures_config.h"
#include "ccf/crypto/curve.h"
#include "ccf/crypto/verifier.h"
#include "ccf/service_signing_keys.h"
#include "crypto/certs.h"
#include "crypto/openssl/ec_key_pair.h"

#include <fmt/format.h>
#include <openssl/crypto.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace ccf
{
  inline ServiceSigningKeys service_signing_keys_from_certificate(
    const std::vector<uint8_t>& certificate)
  {
    return {
      {SigningKeyType::CLASSICAL,
       ccf::crypto::make_unique_verifier(certificate)->public_key_pem()}};
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

  inline ccf::crypto::ECPublicKeyPtr get_previous_service_classical_signing_key(
    const std::optional<ServiceSigningKeys>& keys)
  {
    if (!keys.has_value())
    {
      throw std::logic_error("No previous service identity is configured");
    }
    if (!keys->contains(SigningKeyType::CLASSICAL))
    {
      throw std::logic_error(fmt::format(
        "Missing {} previous service signing public key",
        SigningKeyType::CLASSICAL));
    }
    return ccf::crypto::make_ec_public_key(keys->at(SigningKeyType::CLASSICAL));
  }

  inline ccf::crypto::ECPublicKeyPtr get_previous_service_classical_signing_key(
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

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/cose_signatures_config.h"
#include "ccf/crypto/curve.h"
#include "ccf/crypto/mldsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "crypto/certs.h"
#include "crypto/openssl/ec_key_pair.h"
#include "crypto/openssl/mldsa_support.h"

#include <openssl/crypto.h>
#include <optional>
#include <string>
#include <vector>

namespace ccf
{
  struct NetworkIdentity
  {
    ccf::crypto::Pem priv_key;
    ccf::crypto::Pem cert;
    std::optional<ccf::crypto::Pem> pq_priv_key = std::nullopt;
    std::optional<ccf::crypto::Pem> pq_cert = std::nullopt;

    bool operator==(const NetworkIdentity& other) const = default;

    NetworkIdentity(
      const std::string& subject_name,
      ccf::crypto::CurveID curve_id,
      ccf::crypto::MLDSAParameterSet pq_parameter_set,
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
      create_pq_identity(
        subject_name, pq_parameter_set, valid_from, validity_period_days);
    }

    NetworkIdentity(
      const std::vector<uint8_t>& subject_name_der,
      ccf::crypto::CurveID curve_id,
      ccf::crypto::MLDSAParameterSet pq_parameter_set,
      const std::string& valid_from,
      size_t validity_period_days)
    {
      auto identity_key_pair =
        std::make_shared<ccf::crypto::ECKeyPair_OpenSSL>(curve_id);
      priv_key = identity_key_pair->private_key_pem();

      cert = ccf::crypto::create_self_signed_cert(
        identity_key_pair,
        subject_name_der,
        {} /* SAN */,
        valid_from,
        validity_period_days);
      create_pq_identity(
        subject_name_der, pq_parameter_set, valid_from, validity_period_days);
    }

    NetworkIdentity(const NetworkIdentity& other) = default;

    NetworkIdentity() = default;

    virtual ~NetworkIdentity()
    {
      OPENSSL_cleanse(priv_key.data(), priv_key.size());
      if (pq_priv_key.has_value())
      {
        OPENSSL_cleanse(pq_priv_key->data(), pq_priv_key->size());
      }
    }

    ccf::crypto::Pem renew_certificate(
      const std::string& valid_from, size_t validity_period_days)
    {
      return ccf::crypto::create_self_signed_cert(
        get_key_pair(),
        ccf::crypto::make_verifier(cert)->subject_der(),
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

  private:
    template <typename SubjectName>
    void create_pq_identity(
      const SubjectName& subject_name,
      ccf::crypto::MLDSAParameterSet pq_parameter_set,
      const std::string& valid_from,
      size_t validity_period_days)
    {
      if (!ccf::crypto::mldsa_supported())
      {
        return;
      }

      auto pq_key_pair = ccf::crypto::make_mldsa_key_pair(pq_parameter_set);
      pq_priv_key = pq_key_pair->private_key_pem();
      pq_cert = ccf::crypto::create_self_signed_cert(
        pq_key_pair,
        subject_name,
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }
  };
}

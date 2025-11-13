// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/verifier.h"
#include "ccf/node/cose_signatures_config.h"
#include "crypto/certs.h"
#include "crypto/openssl/ec_key_pair.h"

#include <openssl/crypto.h>
#include <string>
#include <vector>

namespace ccf
{
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

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "ccf/crypto/verifier.h"
#include "ccf/node/cose_signatures_config.h"
#include "crypto/certs.h"
#include "crypto/openssl/key_pair.h"

#include <openssl/crypto.h>
#include <string>
#include <vector>

namespace ccf
{
  struct NetworkIdentity
  {
    ccf::crypto::Pem priv_key;
    ccf::crypto::Pem cert;
    std::string subject_name = "CN=CCF Service"; // TODO: Remove?
    COSESignaturesConfig cose_signatures_config;
    std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> kp{}; // TODO: Remove

    std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> get_key_pair()
    {
      if (!kp)
      {
        kp = std::make_shared<ccf::crypto::KeyPair_OpenSSL>(priv_key);
      }

      return kp;
    }

    bool operator==(const NetworkIdentity& other) const
    {
      return cert == other.cert && priv_key == other.priv_key &&
        subject_name == other.subject_name &&
        cose_signatures_config == other.cose_signatures_config;
    }

    NetworkIdentity(
      const std::string& subject_name_,
      ccf::crypto::CurveID curve_id,
      const std::string& valid_from,
      size_t validity_period_days,
      const COSESignaturesConfig& cose_signatures_config_) :
      subject_name(subject_name_),
      cose_signatures_config(cose_signatures_config_)
    {
      auto identity_key_pair =
        std::make_shared<ccf::crypto::KeyPair_OpenSSL>(curve_id);
      priv_key = identity_key_pair->private_key_pem();

      cert = ccf::crypto::create_self_signed_cert(
        identity_key_pair,
        subject_name,
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    // TODO :Revisit this constructor
    NetworkIdentity(const NetworkIdentity& other) :
      subject_name(ccf::crypto::get_subject_name(other.cert)),
      cose_signatures_config(other.cose_signatures_config)
    {
      priv_key = other.priv_key;
      cert = other.cert;
    }

    NetworkIdentity() = default;

    virtual ~NetworkIdentity()
    {
      OPENSSL_cleanse(priv_key.data(), priv_key.size());
    }

    ccf::crypto::Pem issue_certificate(
      const std::string& valid_from, size_t validity_period_days)
    {
      return ccf::crypto::create_self_signed_cert(
        get_key_pair(),
        subject_name,
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    void set_certificate(const ccf::crypto::Pem& new_cert)
    {
      cert = new_cert;
    }
  };
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/curve.h"
#include "crypto/certs.h"
#include "crypto/openssl/key_pair.h"

#include <openssl/crypto.h>
#include <string>
#include <vector>

namespace ccf
{
  enum class IdentityType
  {
    REPLICATED,
    SPLIT
  };

  struct NetworkIdentity
  {
    ccf::crypto::Pem priv_key;
    ccf::crypto::Pem cert;
    std::optional<IdentityType> type = IdentityType::REPLICATED;
    std::string subject_name = "CN=CCF Service";
    std::shared_ptr<ccf::crypto::KeyPair_OpenSSL> kp{};

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
        type == other.type && subject_name == other.subject_name;
    }

    NetworkIdentity(const std::string& subject_name_) :
      type(IdentityType::REPLICATED),
      subject_name(subject_name_)
    {}
    NetworkIdentity() = default;

    virtual ccf::crypto::Pem issue_certificate(
      const std::string& valid_from, size_t validity_period_days)
    {
      return {};
    }

    virtual void set_certificate(const ccf::crypto::Pem& certificate) {}

    virtual ~NetworkIdentity() {}
  };

  class ReplicatedNetworkIdentity : public NetworkIdentity
  {
  public:
    ReplicatedNetworkIdentity() = default;

    ReplicatedNetworkIdentity(
      const std::string& subject_name_,
      ccf::crypto::CurveID curve_id,
      const std::string& valid_from,
      size_t validity_period_days) :
      NetworkIdentity(subject_name_)
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

    ReplicatedNetworkIdentity(const NetworkIdentity& other) :
      NetworkIdentity(other.subject_name)
    {
      if (type != other.type)
      {
        throw std::runtime_error("invalid identity type conversion");
      }
      priv_key = other.priv_key;
      cert = other.cert;
    }

    virtual ccf::crypto::Pem issue_certificate(
      const std::string& valid_from, size_t validity_period_days) override
    {
      return ccf::crypto::create_self_signed_cert(
        get_key_pair(),
        subject_name,
        {} /* SAN */,
        valid_from,
        validity_period_days);
    }

    virtual void set_certificate(const ccf::crypto::Pem& new_cert) override
    {
      cert = new_cert;
    }

    ~ReplicatedNetworkIdentity() override
    {
      OPENSSL_cleanse(priv_key.data(), priv_key.size());
    }
  };
}
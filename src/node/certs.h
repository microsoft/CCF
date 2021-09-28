// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/x509_time.h"
#include "crypto/pem.h"

#include <string>

namespace ccf
{
  static std::string compute_cert_valid_to_string(
    const std::string& valid_from, size_t validity_period_days)
  {
    // Note: As per RFC 5280, the validity period runs until "notAfter"
    // _inclusive_ so substract one second from the validity period.
    auto valid_to =
      crypto::OpenSSL::adjust_time(valid_from, validity_period_days, -1);
    return crypto::OpenSSL::to_x509_time_string(
      crypto::OpenSSL::to_time_t(valid_to));
  }

  crypto::Pem create_self_signed_cert(
    const crypto::KeyPairPtr& key_pair,
    const crypto::CertificateSubjectIdentity& csi,
    const std::string& valid_from,
    size_t validity_period_days)
  {
    return key_pair->self_sign(
      csi,
      true /* CA */,
      valid_from,
      compute_cert_valid_to_string(valid_from, validity_period_days));
  }
}
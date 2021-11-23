// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "key_pair.h"
#include "openssl/x509_time.h"
#include "pem.h"

#include <string>

namespace crypto
{
  static std::string compute_cert_valid_to_string(
    const std::string& valid_from, size_t validity_period_days)
  {
    // Note: As per RFC 5280, the validity period runs until "notAfter"
    // _inclusive_ so substract one second from the validity period.
    auto valid_to = OpenSSL::adjust_time(valid_from, validity_period_days, -1);
    return OpenSSL::to_x509_time_string(OpenSSL::to_time_t(valid_to));
  }

  static Pem create_self_signed_cert(
    const KeyPairPtr& key_pair,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::string& valid_from,
    size_t validity_period_days)
  {
    return key_pair->self_sign(
      subject_name,
      subject_alt_names,
      true /* CA */,
      valid_from,
      compute_cert_valid_to_string(valid_from, validity_period_days));
  }

  static Pem create_endorsed_cert(
    const Pem& csr,
    const std::string& valid_from,
    const std::string& valid_to,
    const Pem& issuer_key_pair,
    const Pem& issuer_cert)
  {
    return make_key_pair(issuer_key_pair)
      ->sign_csr(issuer_cert, csr, false /* Not CA */, valid_from, valid_to);
  }

  static Pem create_endorsed_cert(
    const Pem& csr,
    const std::string& valid_from,
    size_t validity_period_days,
    const Pem& issuer_key_pair,
    const Pem& issuer_cert)
  {
    return create_endorsed_cert(
      csr,
      valid_from,
      compute_cert_valid_to_string(valid_from, validity_period_days),
      issuer_key_pair,
      issuer_cert);
  }

  static Pem create_endorsed_cert(
    const KeyPairPtr& subject_key_pair,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::string& valid_from,
    size_t validity_period_days,
    const Pem& issuer_key_pair,
    const Pem& issuer_cert)
  {
    return create_endorsed_cert(
      subject_key_pair->create_csr(subject_name, subject_alt_names),
      valid_from,
      validity_period_days,
      issuer_key_pair,
      issuer_cert);
  }
}
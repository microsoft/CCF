// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/crypto/pem.h"
#include "ccf/ds/x509_time_fmt.h"

#include <chrono>
#include <string>

namespace ccf::crypto
{
  static std::string compute_cert_valid_to_string(
    const std::string& valid_from, size_t validity_period_days)
  {
    using namespace std::chrono_literals;
    // Note: As per RFC 5280, the validity period runs until "notAfter"
    // _inclusive_ so substract one second from the validity period.
    auto valid_to = ccf::ds::time_point_from_string(valid_from) +
      std::chrono::days(validity_period_days) - 1s;
    return ccf::ds::to_x509_time_string(valid_to);
  }

  static Pem create_self_signed_cert(
    const ECKeyPairPtr& key_pair,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::string& valid_from,
    const std::string& valid_to)
  {
    return key_pair->self_sign(
      subject_name, valid_from, valid_to, subject_alt_names, true /* CA */);
  }

  static Pem create_self_signed_cert(
    const ECKeyPairPtr& key_pair,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::string& valid_from,
    size_t validity_period_days)
  {
    return create_self_signed_cert(
      key_pair,
      subject_name,
      subject_alt_names,
      valid_from,
      compute_cert_valid_to_string(valid_from, validity_period_days));
  }

  static Pem create_endorsed_cert(
    const Pem& csr,
    const std::string& valid_from,
    const std::string& valid_to,
    const Pem& issuer_private_key,
    const Pem& issuer_cert)
  {
    return make_key_pair(issuer_private_key)
      ->sign_csr(issuer_cert, csr, valid_from, valid_to, false /* Not CA */);
  }

  static Pem create_endorsed_cert(
    const Pem& csr,
    const std::string& valid_from,
    size_t validity_period_days,
    const Pem& issuer_private_key,
    const Pem& issuer_cert)
  {
    return create_endorsed_cert(
      csr,
      valid_from,
      compute_cert_valid_to_string(valid_from, validity_period_days),
      issuer_private_key,
      issuer_cert);
  }

  static Pem create_endorsed_cert(
    const ECKeyPairPtr& subject_key_pair,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::string& valid_from,
    size_t validity_period_days,
    const Pem& issuer_private_key,
    const Pem& issuer_cert)
  {
    return create_endorsed_cert(
      subject_key_pair->create_csr(subject_name, subject_alt_names),
      valid_from,
      validity_period_days,
      issuer_private_key,
      issuer_cert);
  }

  static Pem create_endorsed_cert(
    const Pem& public_key,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::string& valid_from,
    const std::string& valid_to,
    const Pem& issuer_private_key,
    const Pem& issuer_cert,
    bool ca = false)
  {
    auto issuer_key_pair = make_key_pair(issuer_private_key);
    auto csr =
      issuer_key_pair->create_csr(subject_name, subject_alt_names, public_key);
    return issuer_key_pair->sign_csr(
      issuer_cert, csr, valid_from, valid_to, ca, ECKeyPair::Signer::ISSUER);
  }

  static Pem create_endorsed_cert(
    const Pem& public_key,
    const std::string& subject_name,
    const std::vector<SubjectAltName>& subject_alt_names,
    const std::pair<std::string, std::string>& validity_period,
    const Pem& issuer_private_key,
    const Pem& issuer_cert,
    bool ca = false)
  {
    return create_endorsed_cert(
      public_key,
      subject_name,
      subject_alt_names,
      validity_period.first,
      validity_period.second,
      issuer_private_key,
      issuer_cert,
      ca);
  }
}
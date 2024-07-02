// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/certs.h"

ccf::crypto::Pem make_self_signed_cert(ccf::crypto::KeyPairPtr kp)
{
  constexpr size_t certificate_validity_period_days = 365;
  using namespace std::literals;
  const auto valid_from =
    ::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h);

  const auto valid_to = ccf::crypto::compute_cert_valid_to_string(
    valid_from, certificate_validity_period_days);

  return kp->self_sign("CN=Node", valid_from, valid_to);
}

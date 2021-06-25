// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <vector>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include "crypto/openssl/openssl_wrappers.h"

namespace crypto
{
  /** Converts an ECDSA signature in IEEE P1363 encoding to RFC 3279 DER encoding.
   * @param signature The signature in IEEE P1363 encoding
   */
  static std::vector<uint8_t> ecdsa_sig_p1363_to_der(const std::vector<uint8_t>& signature)
  {
    auto signature_size = signature.size();
    auto half_size = signature_size / 2;
    OpenSSL::Unique_BIGNUM r;
    OpenSSL::Unique_BIGNUM s;
    OpenSSL::CHECKNULL(BN_bin2bn(signature.data(), half_size, r));
    OpenSSL::CHECKNULL(BN_bin2bn(signature.data() + half_size, half_size, s));
    OpenSSL::Unique_ECDSA_SIG sig;
    OpenSSL::CHECK1(ECDSA_SIG_set0(sig, r, s));
    r.release();
    s.release();
    auto der_size = i2d_ECDSA_SIG(sig, nullptr);
    OpenSSL::CHECK0(der_size);
    std::vector<uint8_t> der_sig(der_size);
    auto der_sig_buf = der_sig.data();
    OpenSSL::CHECK0(i2d_ECDSA_SIG(sig, &der_sig_buf));
    return der_sig;
  }
}
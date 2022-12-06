// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/openssl/openssl_wrappers.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <vector>

namespace crypto
{
  /** Converts R and S signature parameters to RFC 3279 DER
   * encoding.
   * @param r The raw r signature parameter
   * @param r_size The size of the r signature parameter
   * @param s The raw s signature parameter
   * @param s_size The size of the s signature parameter
   * @param big_endian True if the parameters are big endian, else False
   */
  static std::vector<uint8_t> ecdsa_sig_from_r_s(
    const uint8_t* r,
    size_t r_size,
    const uint8_t* s,
    size_t s_size,
    bool big_endian = true)
  {
    OpenSSL::Unique_BIGNUM r_bn;
    OpenSSL::Unique_BIGNUM s_bn;
    if (big_endian)
    {
      OpenSSL::CHECKNULL(BN_bin2bn(r, r_size, r_bn));
      OpenSSL::CHECKNULL(BN_bin2bn(s, s_size, s_bn));
    }
    else
    {
      OpenSSL::CHECKNULL(BN_lebin2bn(r, r_size, r_bn));
      OpenSSL::CHECKNULL(BN_lebin2bn(s, s_size, s_bn));
    }
    OpenSSL::Unique_ECDSA_SIG sig;
    OpenSSL::CHECK1(ECDSA_SIG_set0(sig, r_bn, s_bn));
    // Ignore previous pointers, as they're now managed by ECDSA_SIG_set0
    // https://www.openssl.org/docs/man1.1.1/man3/ECDSA_SIG_get0.html
    (void)r_bn.release();
    (void)s_bn.release();
    auto der_size = i2d_ECDSA_SIG(sig, nullptr);
    OpenSSL::CHECK0(der_size);
    std::vector<uint8_t> der_sig(der_size);
    auto der_sig_buf = der_sig.data();
    OpenSSL::CHECK0(i2d_ECDSA_SIG(sig, &der_sig_buf));
    return der_sig;
  }

  /** Converts an ECDSA signature in IEEE P1363 encoding to RFC 3279 DER
   * encoding.
   * @param signature The signature in IEEE P1363 encoding
   */
  static std::vector<uint8_t> ecdsa_sig_p1363_to_der(
    const std::vector<uint8_t>& signature)
  {
    auto half_size = signature.size() / 2;
    return ecdsa_sig_from_r_s(
      signature.data(), half_size, signature.data() + half_size, half_size);
  }
}

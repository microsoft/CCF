// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/crypto/ecdsa.h"

#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/public_key.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <vector>

namespace crypto
{
  std::vector<uint8_t> ecdsa_sig_from_r_s(
    const uint8_t* r,
    size_t r_size,
    const uint8_t* s,
    size_t s_size,
    bool big_endian)
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

  std::vector<uint8_t> ecdsa_sig_p1363_to_der(
    const std::vector<uint8_t>& signature)
  {
    auto half_size = signature.size() / 2;
    return ecdsa_sig_from_r_s(
      signature.data(), half_size, signature.data() + half_size, half_size);
  }

  std::vector<uint8_t> ecdsa_sig_der_to_p1363(
    const std::vector<uint8_t>& signature, CurveID curveId)
  {
    auto sig_ptr = signature.data();
    OpenSSL::Unique_ECDSA_SIG ecdsa_sig(
      d2i_ECDSA_SIG(NULL, &sig_ptr, signature.size()));
    // r and s are managed by Unique_ECDSA_SIG object, so we shouldn't use
    // Unique_BIGNUM for them
    const BIGNUM* r = ECDSA_SIG_get0_r(ecdsa_sig);
    const BIGNUM* s = ECDSA_SIG_get0_s(ecdsa_sig);
    int nid = PublicKey_OpenSSL::get_openssl_group_id(curveId);
    OpenSSL::Unique_EC_GROUP ec_group(nid);
    int group_order_bits = EC_GROUP_order_bits(ec_group);
    size_t n = (group_order_bits + 7) / 8;
    std::vector<uint8_t> sig_p1363(n * 2);
    OpenSSL::CHECKEQUAL(n, BN_bn2binpad(r, sig_p1363.data(), n));
    OpenSSL::CHECKEQUAL(n, BN_bn2binpad(s, sig_p1363.data() + n, n));
    return sig_p1363;
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

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
  std::vector<uint8_t> ecdsa_sig_from_r_s(
    const uint8_t* r,
    size_t r_size,
    const uint8_t* s,
    size_t s_size,
    bool big_endian = true);

  /** Converts an ECDSA signature in IEEE P1363 encoding to RFC 3279 DER
   * encoding.
   * @param signature The signature in IEEE P1363 encoding
   */
  std::vector<uint8_t> ecdsa_sig_p1363_to_der(
    const std::vector<uint8_t>& signature);
}

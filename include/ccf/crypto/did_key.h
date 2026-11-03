// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ccf::crypto
{
  /// Encode a NIST EC or RSA SubjectPublicKeyInfo as a canonical did:key.
  /// Throws std::invalid_argument for unsupported or invalid public keys.
  std::string did_key_from_public_key_der(std::span<const uint8_t> der);

  /// Decode and validate a bare, base58btc did:key.
  /// Throws std::invalid_argument for malformed, unsupported or oversized IDs.
  std::vector<uint8_t> public_key_der_from_did_key(std::string_view id);

  /// Compare PEM public keys independently of their point or DER encoding.
  bool public_keys_equal(const Pem& lhs, const Pem& rhs);

  /// Compare the public keys of two DER certificates, independently of their
  /// certificate fields and public-key encoding.
  bool certs_have_same_public_key(
    std::span<const uint8_t> lhs, std::span<const uint8_t> rhs);
}

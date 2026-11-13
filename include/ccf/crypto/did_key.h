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
  /// Encode a NIST EC or RSA SubjectPublicKeyInfo as a base58-btc did:key.
  /// Throws std::invalid_argument for unsupported or invalid public keys.
  std::string did_key_from_public_key_der(std::span<const uint8_t> der);

  /// Encode a public key as did_key_from_public_key_der does, enforcing the
  /// supported key types and sizes but skipping the public key validation,
  /// which is costly for large RSA keys.
  /// Use this to derive the ID that a key would have, to look it up or compare
  /// it with an enrolled ID while authenticating a caller. Use
  /// did_key_from_public_key_der when admitting a new key.
  std::string unvalidated_did_key_from_public_key_der(
    std::span<const uint8_t> der);

  /// Check that a string is a bare base58-btc did:key of acceptable size,
  /// without decoding or validating the key it contains.
  bool is_well_formed_did_key(std::string_view id);

  /// Decode and validate a bare, base58-btc did:key.
  /// Throws std::invalid_argument for malformed, unsupported or oversized IDs,
  /// including the base64url (u) multibase form.
  std::vector<uint8_t> public_key_der_from_did_key(std::string_view id);

  /// Compare PEM public keys independently of their point or DER encoding.
  bool public_keys_equal(const Pem& lhs, const Pem& rhs);

  /// Compare a DER certificate's public key with a DER SubjectPublicKeyInfo.
  bool cert_has_public_key(
    std::span<const uint8_t> cert, std::span<const uint8_t> public_key);
}

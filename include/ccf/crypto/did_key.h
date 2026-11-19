// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ccf::crypto
{
  /// Encode a P-256, P-384 or P-521 SubjectPublicKeyInfo as a base58-btc
  /// did:key. Throws std::invalid_argument for any other key.
  /// The key is not validated, as this derives the ID of keys presented by
  /// unauthenticated callers. A key is validated when its did:key is enrolled,
  /// by public_key_der_from_did_key.
  std::string did_key_from_public_key_der(std::span<const uint8_t> der);

  /// Check that a string is a bare base58-btc did:key of acceptable size,
  /// without decoding or validating the key it contains.
  bool is_well_formed_did_key(std::string_view id);

  /// Decode and validate a bare, base58-btc did:key.
  /// Throws std::invalid_argument for malformed, unsupported or oversized IDs,
  /// including the base64url (u) multibase form.
  std::vector<uint8_t> public_key_der_from_did_key(std::string_view id);
}

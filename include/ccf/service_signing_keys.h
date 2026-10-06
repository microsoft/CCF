// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ccf
{
  // Names of the service signing identity types.
  struct SigningKeyType
  {
    static constexpr auto CLASSICAL = "CLASSICAL";
    static constexpr auto PQ = "PQ";
  };

  // Service signing public keys by identity type. Each key is a CBOR-encoded
  // COSE_Key (RFC 9052 Section 7), which is a base64 string in JSON.
  using ServiceSigningKeys = std::map<std::string, std::vector<uint8_t>>;
}

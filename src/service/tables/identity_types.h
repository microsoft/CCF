// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

#include <cstdint>
#include <map>
#include <stdexcept>
#include <vector>

namespace ccf
{
  enum class IdentityType : uint64_t
  {
    ES384 = 0,
    MLDSA65 = 1,
  };

  DECLARE_JSON_ENUM(
    IdentityType,
    {{IdentityType::ES384, "ES384"}, {IdentityType::MLDSA65, "MLDSA65"}});

  enum class IdentityKind : uint8_t
  {
    RawX509Cert = 0,
    RawX509Key = 1,
    // COSE key and JWK representations may be added here in the future.
  };

  DECLARE_JSON_ENUM(
    IdentityKind,
    {{IdentityKind::RawX509Cert, "RawX509Cert"},
     {IdentityKind::RawX509Key, "RawX509Key"}});

  using IdentityValue = std::vector<uint8_t>;

  struct Identity
  {
    IdentityKind kind;
    IdentityValue value;

    bool operator==(const Identity&) const = default;
  };

  DECLARE_JSON_TYPE(Identity);
  DECLARE_JSON_REQUIRED_FIELDS(Identity, kind, value);

  using Identities = std::map<IdentityType, Identity>;
}

namespace ccf::kv::serialisers
{
  // IdentityType is used as a KV key by tables which were previously a single
  // Value. ES384 is 0, so it serialises to the same bytes as the unit key of
  // those tables, keeping their serialised form unchanged.
  template <>
  struct BlitSerialiser<ccf::IdentityType>
  {
    static SerialisedEntry to_serialised(const ccf::IdentityType& identity_type)
    {
      return BlitSerialiser<uint64_t>::to_serialised(
        static_cast<uint64_t>(identity_type));
    }

    static ccf::IdentityType from_serialised(const SerialisedEntry& data)
    {
      const auto value = BlitSerialiser<uint64_t>::from_serialised(data);
      switch (value)
      {
        case static_cast<uint64_t>(ccf::IdentityType::ES384):
          return ccf::IdentityType::ES384;
        case static_cast<uint64_t>(ccf::IdentityType::MLDSA65):
          return ccf::IdentityType::MLDSA65;
        default:
          throw std::logic_error(
            fmt::format("Unknown identity type: {}", value));
      }
    }
  };
}

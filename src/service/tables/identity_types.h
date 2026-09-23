// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/kv/serialisers/blit_serialiser.h"

#include <cstdint>
#include <format>
#include <map>
#include <stdexcept>
#include <vector>

namespace ccf
{
  /// Cryptographic family of an identity.
  // Preserve the existing 64-bit C++ representation.
  // NOLINTNEXTLINE(performance-enum-size)
  enum class IdentityType : uint64_t
  {
    /// Classical cryptographic identity.
    CLASSICAL = 0,
    /// Post-quantum cryptographic identity.
    PQ = 1,
  };

  DECLARE_JSON_ENUM(
    IdentityType,
    {{IdentityType::CLASSICAL, "CLASSICAL"}, {IdentityType::PQ, "PQ"}});

  /// Encoding of the certificate or public key held by an identity.
  enum class IdentityKind : uint8_t
  {
    /// DER-encoded X.509 certificate.
    X509_CERT_DER = 0,
    /// DER-encoded X.509 SubjectPublicKeyInfo public key.
    X509_SPKI_DER = 1,
  };

  DECLARE_JSON_ENUM(
    IdentityKind,
    {{IdentityKind::X509_CERT_DER, "X509_CERT_DER"},
     {IdentityKind::X509_SPKI_DER, "X509_SPKI_DER"}});

  using IdentityValue = std::vector<uint8_t>;

  /// An encoded certificate or public key.
  struct Identity
  {
    /// Encoding of the identity material.
    IdentityKind kind = IdentityKind::X509_CERT_DER;
    /// Certificate or public-key bytes in the encoding specified by kind.
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
  // Value. CLASSICAL is 0, so it serialises to the same bytes as the unit key
  // of those tables, keeping their serialised form unchanged.
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
        case static_cast<uint64_t>(ccf::IdentityType::CLASSICAL):
          return ccf::IdentityType::CLASSICAL;
        case static_cast<uint64_t>(ccf::IdentityType::PQ):
          return ccf::IdentityType::PQ;
        default:
          throw std::logic_error(
            std::format("Unknown identity type: {}", value));
      }
    }
  };
}

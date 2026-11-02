// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/cose_key.h"
#include "ccf/crypto/ec_public_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/service/map.h"
#include "ccf/service/tables/service.h"
#include "ccf/tx.h"
#include "crypto/cose.h"
#include "service/tables/identity_types.h"

#include <optional>
#include <stdexcept>

namespace ccf
{
  using SigningIdentities = ServiceMap<IdentityType, Identity>;

  namespace Tables
  {
    static constexpr auto SIGNING_IDENTITIES =
      "public:ccf.gov.service.signing_identities";
  }

  inline ccf::crypto::COSEKey cose_key_from_identity(const Identity& identity)
  {
    switch (identity.kind)
    {
      case IdentityKind::X509_CERT_DER:
      {
        return ccf::crypto::COSEKey::from_der_cert(identity.value);
      }
      case IdentityKind::X509_SPKI_DER:
      {
        return ccf::crypto::COSEKey(
          ccf::crypto::make_ec_public_key(identity.value));
      }
      case IdentityKind::COSE_KEY:
      {
        return ccf::crypto::COSEKey::from_cbor(identity.value);
      }
    }
    throw std::logic_error("Unknown identity kind");
  }

  // Encode an EC public key with its curve's ledger signing algorithm.
  inline Identity signing_identity_from_key(const ccf::crypto::COSEKey& key)
  {
    const auto ec_key = key.ec_public_key();
    if (ec_key == nullptr)
    {
      throw std::logic_error("Service signing key must be an EC key");
    }
    return {
      IdentityKind::COSE_KEY,
      key.to_cbor(cose::algorithm_for_curve(ec_key->get_curve_id()).alg)};
  }

  inline Identity signing_identity_from_cert(const ccf::crypto::Pem& cert)
  {
    return signing_identity_from_key(
      ccf::crypto::COSEKey::from_der_cert(ccf::crypto::cert_pem_to_der(cert)));
  }

  // Compare public keys across identity encodings.
  inline bool is_same_key(
    const Identity& identity, const std::vector<uint8_t>& public_key_der)
  {
    return signing_identity_from_key(cose_key_from_identity(identity)) ==
      signing_identity_from_key(cose_key_from_identity(
        {IdentityKind::X509_SPKI_DER, public_key_der}));
  }

  // Return the CLASSICAL entry unchanged, or the service certificate's key
  // if absent (legacy services and live updates). PQ is unsupported.
  inline std::optional<Identity> get_service_signing_identity(
    ccf::kv::ReadOnlyTx& tx, IdentityType identity_type)
  {
    if (identity_type != IdentityType::CLASSICAL)
    {
      throw std::logic_error("PQ signing identities are not supported yet");
    }

    auto signing_identity =
      tx.ro<SigningIdentities>(Tables::SIGNING_IDENTITIES)->get(identity_type);
    if (signing_identity.has_value())
    {
      return signing_identity;
    }

    const auto service_info = tx.ro<Service>(Tables::SERVICE)->get();
    if (!service_info.has_value())
    {
      return std::nullopt;
    }
    return signing_identity_from_cert(service_info->cert);
  }

  // Require matching public keys when both records are present.
  inline void check_signing_identity_matches_service_cert(
    const std::optional<Identity>& published_identity,
    const std::optional<ServiceInfo>& service_info)
  {
    if (!published_identity.has_value() || !service_info.has_value())
    {
      return;
    }

    if (
      signing_identity_from_key(cose_key_from_identity(*published_identity)) !=
      signing_identity_from_cert(service_info->cert))
    {
      throw std::logic_error(
        "Service signing identity does not match its service certificate");
    }
  }

  inline void check_signing_identity_matches_service_cert(
    ccf::kv::ReadOnlyTx& tx)
  {
    check_signing_identity_matches_service_cert(
      tx.ro<SigningIdentities>(Tables::SIGNING_IDENTITIES)
        ->get(IdentityType::CLASSICAL),
      tx.ro<Service>(Tables::SERVICE)->get());
  }
}

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
        return ccf::crypto::COSEKey::from_der_public_key(identity.value);
      }
      case IdentityKind::COSE_KEY:
      {
        return ccf::crypto::COSEKey::from_cbor(identity.value);
      }
    }
    throw std::logic_error("Unknown identity kind");
  }

  // Encode a public key with its service signing algorithm.
  inline Identity signing_identity_from_key(const ccf::crypto::COSEKey& key)
  {
    const auto ec_key = key.ec_public_key();
    if (ec_key != nullptr)
    {
      return {
        IdentityKind::COSE_KEY,
        key.to_cbor(cose::algorithm_for_curve(ec_key->get_curve_id()).alg)};
    }

    const auto pq_key = key.mldsa_public_key();
    if (pq_key != nullptr)
    {
      return {
        IdentityKind::COSE_KEY,
        key.to_cbor(
          cose::algorithm_for_parameter_set(pq_key->get_parameter_set()))};
    }
    throw std::logic_error("Service signing key must be an EC or ML-DSA key");
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

  // CLASSICAL permits legacy records; PQ requires both records or neither.
  inline void check_signing_identity_matches_service_cert(
    const std::optional<Identity>& published_identity,
    const std::optional<ServiceInfo>& service_info,
    IdentityType identity_type = IdentityType::CLASSICAL)
  {
    std::optional<ccf::crypto::Pem> cert;
    switch (identity_type)
    {
      case IdentityType::CLASSICAL:
      {
        if (!published_identity.has_value() || !service_info.has_value())
        {
          return;
        }
        cert = service_info->cert;
        break;
      }
      case IdentityType::PQ:
      {
        if (service_info.has_value())
        {
          cert = service_info->pq_cert;
        }
        if (published_identity.has_value() != cert.has_value())
        {
          throw std::logic_error(
            "PQ signing identity and service certificate must both be present "
            "or absent");
        }
        if (!published_identity.has_value())
        {
          return;
        }
        break;
      }
      default:
      {
        throw std::logic_error("Unknown service signing identity type");
      }
    }

    const auto key = cose_key_from_identity(published_identity.value());
    if (
      identity_type == IdentityType::PQ &&
      (published_identity->kind != IdentityKind::COSE_KEY ||
       key.kty() != ccf::crypto::COSEKeyType::AKP))
    {
      throw std::logic_error("PQ signing identity must be an ML-DSA COSE_Key");
    }
    if (
      signing_identity_from_key(key) !=
      signing_identity_from_cert(cert.value()))
    {
      throw std::logic_error(
        "Service signing identity does not match its service certificate");
    }
  }

  inline void check_signing_identity_matches_service_cert(
    ccf::kv::ReadOnlyTx& tx)
  {
    auto* identities = tx.ro<SigningIdentities>(Tables::SIGNING_IDENTITIES);
    const auto service_info = tx.ro<Service>(Tables::SERVICE)->get();
    check_signing_identity_matches_service_cert(
      identities->get(IdentityType::CLASSICAL), service_info);
    check_signing_identity_matches_service_cert(
      identities->get(IdentityType::PQ), service_info, IdentityType::PQ);
  }

  // CLASSICAL keeps its legacy certificate fallback. PQ never falls back.
  inline std::optional<Identity> get_service_signing_identity(
    ccf::kv::ReadOnlyTx& tx, IdentityType identity_type)
  {
    if (
      identity_type != IdentityType::CLASSICAL &&
      identity_type != IdentityType::PQ)
    {
      throw std::logic_error("Unknown service signing identity type");
    }

    auto signing_identity =
      tx.ro<SigningIdentities>(Tables::SIGNING_IDENTITIES)->get(identity_type);
    if (identity_type == IdentityType::PQ)
    {
      check_signing_identity_matches_service_cert(
        signing_identity,
        tx.ro<Service>(Tables::SERVICE)->get(),
        identity_type);
      return signing_identity;
    }
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
}

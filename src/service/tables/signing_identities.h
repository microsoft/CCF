// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/verifier.h"
#include "ccf/service/map.h"
#include "ccf/service/tables/service.h"
#include "ccf/tx.h"
#include "service/tables/identity_types.h"

#include <optional>

namespace ccf
{
  using SigningIdentities = ServiceMap<IdentityType, Identity>;

  namespace Tables
  {
    static constexpr auto SIGNING_IDENTITIES =
      "public:ccf.gov.service.signing_identities";
  }

  inline std::optional<Identity> get_service_signing_identity(
    ccf::kv::ReadOnlyTx& tx, IdentityType identity_type)
  {
    auto* signing_identities =
      tx.ro<SigningIdentities>(Tables::SIGNING_IDENTITIES);
    auto signing_identity = signing_identities->get(identity_type);
    if (signing_identity.has_value())
    {
      if (signing_identity->kind != IdentityKind::X509_SPKI_DER)
      {
        throw std::logic_error(
          "Service signing identity must be a DER SubjectPublicKeyInfo");
      }
      return signing_identity;
    }

    if (identity_type == IdentityType::CLASSICAL)
    {
      if (signing_identities->size() != 0)
      {
        throw std::logic_error(
          "Non-empty signing identities table has no CLASSICAL identity");
      }

      // Legacy ledgers have no signing identities, only a service certificate.
      const auto service_info = tx.ro<Service>(Tables::SERVICE)->get();
      if (service_info.has_value())
      {
        const auto cert_der = ccf::crypto::cert_pem_to_der(service_info->cert);
        return Identity{
          IdentityKind::X509_SPKI_DER,
          ccf::crypto::public_key_der_from_cert(cert_der)};
      }
    }

    return std::nullopt;
  }
}

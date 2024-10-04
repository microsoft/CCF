// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/kv/value.h"

#include <string>
#include <vector>

namespace ccf
{
  using PreviousServiceIdentity = ServiceValue<ccf::crypto::Pem>;

  struct CoseEndorsement
  {
    std::vector<uint8_t> endorsement{};
    std::vector<uint8_t> endorsing_key{};
    std::optional<ccf::kv::Version> previous_version{};
    std::optional<std::pair<ccf::TxID, ccf::TxID>> endorsed_range{};
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CoseEndorsement);
  DECLARE_JSON_REQUIRED_FIELDS(CoseEndorsement, endorsement, endorsing_key);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CoseEndorsement, previous_version, endorsed_range);

  using PreviousServiceIdentityEndorsement = ServiceValue<CoseEndorsement>;

  namespace Tables
  {
    static constexpr auto PREVIOUS_SERVICE_IDENTITY =
      "public:ccf.gov.service.previous_service_identity";
    static constexpr auto PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT =
      "public:ccf.gov.service.previous_service_identity_endorsement";
  }
}
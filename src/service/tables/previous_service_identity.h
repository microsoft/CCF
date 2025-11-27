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

  using PreviousServiceLastSignedRoot = ServiceValue<ccf::crypto::Sha256Hash>;

  struct CoseEndorsement
  {
    /// COSE-sign of the a previous service identity's public key.
    std::vector<uint8_t> endorsement;

    /// Service key at the moment of endorsing.
    std::vector<uint8_t> endorsing_key;

    /// The transaction ID when the *endorsed* service was created.
    ccf::TxID endorsement_epoch_begin;

    /// Last transaction ID that the endorsement is valid for. Only present for
    /// previouse services endorsements, self-endorsed services must not have
    /// this set.
    std::optional<ccf::TxID> endorsement_epoch_end;

    /// Pointer to the previous CoseEndorsement entry. Only present for previous
    /// service endorsements, self-endorsed services must not have this set.
    std::optional<ccf::kv::Version> previous_version;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(CoseEndorsement);
  DECLARE_JSON_REQUIRED_FIELDS(
    CoseEndorsement, endorsement, endorsement_epoch_begin, endorsing_key);
  DECLARE_JSON_OPTIONAL_FIELDS(
    CoseEndorsement, previous_version, endorsement_epoch_end);

  using PreviousServiceIdentityEndorsement = ServiceValue<CoseEndorsement>;

  namespace Tables
  {
    static constexpr auto PREVIOUS_SERVICE_IDENTITY =
      "public:ccf.gov.service.previous_service_identity";
    static constexpr auto PREVIOUS_SERVICE_LAST_SIGNED_ROOT =
      "public:ccf.internal.previous_service_last_signed_root";
    static constexpr auto PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT =
      "public:ccf.internal.previous_service_identity_endorsement";
  }
}
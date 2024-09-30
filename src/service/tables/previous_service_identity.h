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

  using ServiceEndorsement = std::vector<uint8_t>;
  using PreviousServiceIdentityEndorsement = ServiceValue<ServiceEndorsement>;

  namespace Tables
  {
    static constexpr auto PREVIOUS_SERVICE_IDENTITY =
      "public:ccf.gov.service.previous_service_identity";
    static constexpr auto PREVIOUS_SERVICE_IDENTITY_ENDORSEMENT =
      "public:ccf.gov.service.previous_service_identity_endorsement";
  }
}
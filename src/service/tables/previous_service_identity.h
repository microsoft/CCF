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

  namespace Tables
  {
    static constexpr auto PREVIOUS_SERVICE_IDENTITY =
      "public:ccf.gov.service.previous_service_identity";
  }
}
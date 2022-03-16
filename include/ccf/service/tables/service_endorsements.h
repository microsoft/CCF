// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/service/map.h"

namespace ccf
{
  using RecoveryID = uint64_t;
  using ServiceEndorsements = ServiceMap<RecoveryID, crypto::Pem>;
  namespace Tables
  {
    static constexpr auto SERVICE_ENDORSEMENTS =
      "public:ccf.service.endorsements";
  }
}
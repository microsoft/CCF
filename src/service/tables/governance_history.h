// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/service/signed_req.h"
#include "service/map.h"

namespace ccf
{
  using GovernanceHistory = ServiceMap<MemberId, SignedReq>;
  namespace Tables
  {
    static constexpr auto GOV_HISTORY = "public:ccf.gov.history";
  }
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "ccf/service/map.h"
#include "ccf/service/signed_req.h"

namespace ccf
{
  using GovernanceHistory = ServiceMap<MemberId, SignedReq>;
  namespace Tables
  {
    static constexpr auto GOV_HISTORY = "public:ccf.gov.history";
  }
  using COSEGovernanceHistory = ServiceMap<MemberId, std::vector<uint8_t>>;
  namespace Tables
  {
    static constexpr auto COSE_GOV_HISTORY = "public:ccf.gov.cose_history";
  }
  using COSERecentProposals =
    ServiceMap<std::string, std::string /* ProposalId */>;
  namespace Tables
  {
    static constexpr auto COSE_RECENT_PROPOSALS =
      "public:ccf.gov.cose_recent_proposals";
  }
}
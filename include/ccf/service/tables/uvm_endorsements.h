// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

#include <string>

namespace ccf
{
  struct UVMEndorsementsData
  {
    size_t svn;

    bool operator==(const UVMEndorsementsData&) const = default;
  };
  DECLARE_JSON_TYPE(UVMEndorsementsData);
  DECLARE_JSON_REQUIRED_FIELDS(UVMEndorsementsData, svn);

  using DID = std::string;
  using Feed = std::string;
  using FeedToEndorsementsDataMap = std::map<Feed, UVMEndorsementsData>;

  using SNPUVMEndorsements = ServiceMap<DID, FeedToEndorsementsDataMap>;

  namespace Tables
  {
    static constexpr auto NODE_SNP_UVM_ENDORSEMENTS =
      "public:ccf.gov.nodes.snp.uvm_endorsements";
  }
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

#include <string>

namespace ccf
{
  struct UVMEndorsementsData
  {
    std::string did;
    std::string feed;
    size_t svn;

    bool operator==(const UVMEndorsementsData&) const = default;

    bool operator>=(const UVMEndorsementsData& other) const
    {
      return did == other.did && feed == other.feed && svn >= other.svn;
    }
  };
  DECLARE_JSON_TYPE(UVMEndorsementsData);
  DECLARE_JSON_REQUIRED_FIELDS(UVMEndorsementsData, did, feed, svn);

  using SnpUVMEndorsements = ServiceSet<UVMEndorsementsData>;

  namespace Tables
  {
    static constexpr auto NODE_SNP_UVM_ENDORSEMENTS =
      "public:ccf.gov.nodes.snp.uvm.endorsements";
  }
}
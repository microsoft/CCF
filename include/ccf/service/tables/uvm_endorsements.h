// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/map.h"

#include <string>

namespace ccf
{
  struct UVMEndorsementsData
  {
    std::string feed;
    size_t svn;
  };
  DECLARE_JSON_TYPE(UVMEndorsementsData);
  DECLARE_JSON_REQUIRED_FIELDS(UVMEndorsementsData, feed, svn);

  using DID = std::string;

  using SnpUVMEndorsements = ServiceMap<DID, UVMEndorsementsData>;

  namespace Tables
  {
    static constexpr auto NODE_SNP_UVM_MEASUREMENTS =
      "public:ccf.gov.nodes.snp.uvm.measurements";
  }
}
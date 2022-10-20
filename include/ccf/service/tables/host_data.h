// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/service/map.h"

using HostData = crypto::Sha256Hash;
using HostDataMetadata = std::string;

namespace ccf
{
  using SnpHostDataMap = ServiceMap<HostData, HostDataMetadata>;
  namespace Tables
  {
    static constexpr auto HOST_DATA = "public:ccf.gov.nodes.snp.host_data";
  }
}
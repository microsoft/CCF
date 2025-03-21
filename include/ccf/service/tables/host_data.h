// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"
#include "ccf/service/map.h"

using HostData = ccf::crypto::Sha256Hash;
using HostDataMetadata =
  std::string; // Optional raw (i.e. not base64-encoded) policy

namespace ccf
{
  using SnpHostDataMap = ServiceMap<HostData, HostDataMetadata>;
  using VirtualHostDataMap = ServiceSet<HostData>;
  namespace Tables
  {
    static constexpr auto HOST_DATA = "public:ccf.gov.nodes.snp.host_data";
    static constexpr auto VIRTUAL_HOST_DATA =
      "public:ccf.gov.nodes.virtual.host_data";
  }
}
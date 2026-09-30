// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/pal/measurement.h"

#include <string>
#include <vector>

namespace ccf
{
  using DID = std::string;
  using Feed = std::string;
}

namespace ccf::pal
{
  struct UVMEndorsements
  {
    DID did;
    Feed feed;
    std::string svn;

    bool operator==(const UVMEndorsements&) const = default;

    std::string to_str()
    {
      return fmt::format("did: {}, feed: {}, svn: {}", did, feed, svn);
    }
  };
  DECLARE_JSON_TYPE(UVMEndorsements);
  DECLARE_JSON_REQUIRED_FIELDS(UVMEndorsements, did, feed, svn);

  UVMEndorsements verify_uvm_endorsements_descriptor(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement);
}
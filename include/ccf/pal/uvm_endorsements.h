// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/uvm_endorsements.h"

namespace ccf::pal
{
  struct UVMEndorsements
  {
    DID did;
    Feed feed;
    std::string svn;

    bool operator==(const UVMEndorsements&) const = default;

    inline std::string to_str()
    {
      return fmt::format("did: {}, feed: {}, svn: {}", did, feed, svn);
    }
  };
  DECLARE_JSON_TYPE(UVMEndorsements);
  DECLARE_JSON_REQUIRED_FIELDS(UVMEndorsements, did, feed, svn);

  /**
   * @brief Verifies the UVM (Utility Virtual Machine) endorsements
   * descriptor.
   *
   * This function processes raw UVM endorsements data and validates it against
   * the provided platform attestation measurement. It ensures that the
   * endorsements are authentic and match the expected measurement.
   *
   * @param uvm_endorsements_raw A vector of raw bytes representing the UVM
   * endorsements.
   * @param uvm_measurement The platform attestation measurement to validate
   * against.
   * @return A UVMEndorsements object containing the parsed and verified
   * endorsements.
   * @throws std::runtime_error if the endorsements cannot be verified.
   */
  UVMEndorsements verify_uvm_endorsements_descriptor(
    const std::vector<uint8_t>& uvm_endorsements_raw,
    const pal::PlatformAttestationMeasurement& uvm_measurement);
}
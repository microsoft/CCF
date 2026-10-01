// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/app_interface.h"
#include "ccf/js/common_context.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/version.h"

#include <didx509cpp/didx509cpp.h>
#include <iostream>
#include <tav/cbor.hpp>
#include <tav/snp.h>
#include <tav/utils.h>
#include <vector>

using namespace std;
using namespace nlohmann;

namespace ccf
{
  std::unique_ptr<ccf::endpoints::EndpointRegistry> make_user_endpoints(
    ccf::AbstractNodeContext& context)
  {
    return std::make_unique<ccf::UserEndpointRegistry>(context);
  }
}

int main()
{
  std::cout << "I'm a CCF test app " << ccf::ccf_version << std::endl;

  // Third-party headers installed for applications must be usable
  namespace cbor = tav::cbor;
  const std::vector<uint8_t> bytes = {0x01, 0x02};
  std::vector<cbor::MapItem> entries;
  entries.emplace_back(cbor::make_signed(-1), cbor::make_bytes(bytes));
  entries.emplace_back(cbor::make_signed(1), cbor::make_string("ccfapp"));
  const auto encoded = cbor::make_map(std::move(entries)).det_serialize();
  // Deterministic encoding sorts the keys: {1: "ccfapp", -1: h'0102'}
  const std::vector<uint8_t> expected = {
    0xa2, 0x01, 0x66, 'c', 'c', 'f', 'a', 'p', 'p', 0x20, 0x42, 0x01, 0x02};
  if (
    encoded != expected ||
    cbor::det_parse(encoded).map_at(cbor::make_signed(1)).as_string() !=
      "ccfapp")
  {
    std::cerr << "Unexpected TAV CBOR round trip" << std::endl;
    return 1;
  }

  const std::vector<uint8_t> malformed_report(16, 0);
  TavSnpAttestationReport* raw_report = nullptr;
  TavError* error = tav_snp_attestation_report_from_unverified_bytes(
    malformed_report.data(), malformed_report.size(), &raw_report);
  const ccf::pal::snp::AttestationReport report(raw_report);
  const bool rejected = error != nullptr && report == nullptr;
  tav_error_free(error);
  if (!rejected)
  {
    std::cerr << "TAV accepted a malformed SNP report" << std::endl;
    return 1;
  }

  std::cout << "Exported headers are usable" << std::endl;
}
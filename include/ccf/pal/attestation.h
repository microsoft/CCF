// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/quote_info.h"
#include "ccf/pal/attestation_sev_snp_endorsements.h"
#include "ccf/pal/measurement.h"
#include "ccf/pal/report_data.h"

#include <functional>

namespace ccf::pal
{
  // Caller-supplied callback used to retrieve endorsements as specified by
  // the config argument. When called back, the quote_info argument will have
  // already been populated with the raw quote.
  using RetrieveEndorsementCallback = std::function<void(
    const QuoteInfo& quote_info,
    const snp::EndorsementEndpointsConfiguration& config)>;

  void verify_virtual_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data);

  void verify_snp_attestation_report(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data);

  void verify_quote(
    const QuoteInfo& quote_info,
    PlatformAttestationMeasurement& measurement,
    PlatformAttestationReportData& report_data);

  class AttestationCollateralFetchingTimeout : public std::exception
  {
  private:
    std::string msg;

  public:
    AttestationCollateralFetchingTimeout(const std::string& msg_) : msg(msg_) {}

    [[nodiscard]] virtual const char* what() const throw()
    {
      return msg.c_str();
    }
  };
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/http_status.h"
#include "ccf/node/quote.h"

namespace ccf {
    static std::pair<http_status, std::string> quote_verification_error(
      QuoteVerificationResult result)
    {
      switch (result)
      {
        case QuoteVerificationResult::Failed:
          return std::make_pair(
            HTTP_STATUS_UNAUTHORIZED, "Quote could not be verified");
        case QuoteVerificationResult::FailedMeasurementNotFound:
          return std::make_pair(
            HTTP_STATUS_UNAUTHORIZED,
            "Quote does not contain known enclave measurement");
        case QuoteVerificationResult::FailedInvalidQuotedPublicKey:
          return std::make_pair(
            HTTP_STATUS_UNAUTHORIZED,
            "Quote report data does not contain node's public key hash");
        case QuoteVerificationResult::FailedHostDataDigestNotFound:
          return std::make_pair(
            HTTP_STATUS_UNAUTHORIZED,
            "Quote does not contain trusted host data");
        case QuoteVerificationResult::FailedInvalidHostData:
          return std::make_pair(
            HTTP_STATUS_UNAUTHORIZED, "Quote host data is not authorised");
        case ccf::QuoteVerificationResult::FailedUVMEndorsementsNotFound:
          return std::make_pair(
            HTTP_STATUS_UNAUTHORIZED, "UVM endorsements are not authorised");
        default:
          return std::make_pair(
            HTTP_STATUS_INTERNAL_SERVER_ERROR,
            "Unknown quote verification error");
      }
    }
}
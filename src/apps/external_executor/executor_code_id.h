// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/node/quote.h"
#include "ccf/pal/attestation_sev_snp.h"
#include "ccf/pal/measurement.h"
#include "ccf/service/map.h"
#include "ccf/service/tables/code_id.h"
#include "endpoints/grpc/status.h"
#include "executor_registration.pb.h"

namespace externalexecutor
{
  // stub out quote verification until we have SEV-SNP verification
  inline ccf::QuoteVerificationResult verify_executor_quote(
    kv::ReadOnlyTx& tx,
    const externalexecutor::protobuf::Attestation& quote_info,
    const std::string& expected_node_public_key_der,
    ccf::pal::PlatformAttestationMeasurement& measurement)
  {
    return ccf::QuoteVerificationResult::Verified;
  }

  inline std::pair<grpc_status, std::string> verification_error(
    ccf::QuoteVerificationResult result)
  {
    switch (result)
    {
      case ccf::QuoteVerificationResult::Failed:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED, "Quote could not be verified");
      case ccf::QuoteVerificationResult::FailedMeasurementNotFound:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED,
          "Quote does not contain known enclave measurement");
      case ccf::QuoteVerificationResult::FailedInvalidQuotedPublicKey:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED,
          "Quote report data does not contain node's public key hash");
      case ccf::QuoteVerificationResult::FailedHostDataDigestNotFound:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED, "Quote does not contain host data");
      case ccf::QuoteVerificationResult::FailedInvalidHostData:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED, "Quote host data is not authorised");
      case ccf::QuoteVerificationResult::FailedUVMEndorsementsNotFound:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED, "UVM endorsements are not authorised");
      default:
        return std::make_pair(
          GRPC_STATUS_INTERNAL, "Unknown quote verification error");
    }
  }

  enum class ExecutorCodeStatus
  {
    ALLOWED_TO_EXECUTE = 0
  };

  DECLARE_JSON_ENUM(
    ExecutorCodeStatus,
    {{ExecutorCodeStatus::ALLOWED_TO_EXECUTE, "AllowedToExecute"}});

  struct GetExecutorCode
  {
    struct Version
    {
      std::string digest;
      ExecutorCodeStatus status;
      std::optional<ccf::QuoteFormat> platform;
    };

    struct Out
    {
      std::vector<GetExecutorCode::Version> versions = {};
    };
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(GetExecutorCode::Version)
  DECLARE_JSON_REQUIRED_FIELDS(GetExecutorCode::Version, digest, status)
  DECLARE_JSON_OPTIONAL_FIELDS(GetExecutorCode::Version, platform)
  DECLARE_JSON_TYPE(GetExecutorCode::Out)
  DECLARE_JSON_REQUIRED_FIELDS(GetExecutorCode::Out, versions)

  struct ExecutorCodeInfo
  {
    ExecutorCodeStatus status;
    ccf::QuoteFormat platform;
  };

  DECLARE_JSON_TYPE(ExecutorCodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(ExecutorCodeInfo, status, platform);

  using ExecutorCodeIDs =
    ccf::ServiceMap<ccf::pal::SnpAttestationMeasurement, ExecutorCodeInfo>;

  static constexpr auto EXECUTOR_CODE_IDS =
    "public:ccf.gov.nodes.executor_code_ids";
} // namespace externalexecutor
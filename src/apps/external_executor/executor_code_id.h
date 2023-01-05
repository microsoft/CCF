// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/node/quote.h"
#include "ccf/service/code_digest.h"
#include "ccf/service/map.h"
#include "ccf/service/tables/code_id.h"
#include "endpoints/grpc/status.h"
#include "executor_registration.pb.h"

namespace externalexecutor
{
  enum class ExecutorCodeStatus
  {
    ALLOWED_TO_EXECUTE = 0
  };

  DECLARE_JSON_ENUM(
    ExecutorCodeStatus,
    {{ExecutorCodeStatus::ALLOWED_TO_EXECUTE, "AllowedToExecute"}});

  // TODO: Remove this, use generic KV endpoint
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

  using ExecutorCodeIDs = ccf::ServiceMap<ccf::CodeDigest, ExecutorCodeInfo>;

  namespace Tables
  {
    static constexpr auto EXECUTOR_CODE_IDS =
      "public:ccf.gov.nodes.executor_code_ids";
  }

  // stub out quote verification until we have SEV-SNP verification
  inline ccf::QuoteVerificationResult verify_executor_quote(
    kv::ReadOnlyTx& tx,
    const externalexecutor::protobuf::Attestation& attestation,
    const std::string&
      expected_executor_public_key_der, // TODO: Der? Surely pem?
    ccf::CodeDigest& code_digest)
  {
    switch (attestation.format())
    {
      case externalexecutor::protobuf::Attestation::OE_SGX_V1:
      case externalexecutor::protobuf::Attestation::AMD_SEV_SNP_V1:
      {
        LOG_FAIL_FMT(
          "Executor attestation verification currently stubbed out - passing "
          "without check");
        return ccf::QuoteVerificationResult::Verified;
      }
      case externalexecutor::protobuf::Attestation::INSECURE_VIRTUAL:
      {
        // Fake a virtual attestation. Quote should be a known, permitted code
        // ID. Note this does no cryptographic verification, and does not bind
        // to a specific executor public key.
        const auto& quote = attestation.quote();
        try
        {
          ds::from_hex(quote, code_digest.data.begin(), code_digest.data.end());

          const bool known =
            tx.ro<ExecutorCodeIDs>(Tables::EXECUTOR_CODE_IDS)->has(code_digest);
          if (known)
          {
            return ccf::QuoteVerificationResult::Verified;
          }
          else
          {
            return ccf::QuoteVerificationResult::FailedCodeIdNotFound;
          }
        }
        catch (const std::logic_error& e)
        {
          LOG_FAIL_FMT(
            "Failed to convert virtual attestation to code digest: {}",
            e.what());
          return ccf::QuoteVerificationResult::Failed;
        }
      }
      default:
      {
        LOG_FAIL_FMT(
          "Unexpected attestation format for executor: {}",
          externalexecutor::protobuf::Attestation::Format_Name(
            attestation.format()));
        return ccf::QuoteVerificationResult::Failed;
      }
    }
  }

  inline std::pair<grpc_status, std::string> verification_error(
    ccf::QuoteVerificationResult result)
  {
    switch (result)
    {
      case ccf::QuoteVerificationResult::Failed:
        return std::make_pair(
          GRPC_STATUS_UNAUTHENTICATED, "Quote could not be verified");
      case ccf::QuoteVerificationResult::FailedCodeIdNotFound:
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
      default:
        return std::make_pair(
          GRPC_STATUS_INTERNAL, "Unknown quote verification error");
    }
  }
} // namespace externalexecutor
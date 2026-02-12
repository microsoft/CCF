// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/http_status.h"

namespace ccf
{
  struct ODataAuthErrorDetails
  {
    std::string auth_policy;
    std::string code;
    std::string message;

    bool operator==(const ODataAuthErrorDetails&) const = default;
  };

  DECLARE_JSON_TYPE(ODataAuthErrorDetails);
  DECLARE_JSON_REQUIRED_FIELDS(
    ODataAuthErrorDetails, auth_policy, code, message);

  struct ODataJSExceptionDetails
  {
    std::string code;
    std::string message;
    std::optional<std::string> trace;

    bool operator==(const ODataJSExceptionDetails&) const = default;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ODataJSExceptionDetails);
  DECLARE_JSON_REQUIRED_FIELDS(ODataJSExceptionDetails, code, message);
  DECLARE_JSON_OPTIONAL_FIELDS(ODataJSExceptionDetails, trace);

  struct ODataError
  {
    std::string code;
    std::string message;
    std::vector<nlohmann::json> details;

    bool operator==(const ODataError&) const = default;
  };

  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(ODataError);
  DECLARE_JSON_REQUIRED_FIELDS(ODataError, code, message);
  DECLARE_JSON_OPTIONAL_FIELDS(ODataError, details);

  struct ODataErrorResponse
  {
    ODataError error;
  };

  DECLARE_JSON_TYPE(ODataErrorResponse);
  DECLARE_JSON_REQUIRED_FIELDS(ODataErrorResponse, error);

  struct ErrorDetails
  {
    http_status status = HTTP_STATUS_BAD_REQUEST;
    std::string code;
    std::string msg;
  };

  namespace errors
  {
#define ERROR(code) constexpr const char* code = #code;

    // For inspiration, see:
    // https://docs.microsoft.com/en-us/rest/api/storageservices/common-rest-api-error-codes

    // Generic errors
    ERROR(AuthorizationFailed)
    ERROR(InternalError)
    ERROR(NotImplemented)
    ERROR(InvalidAuthenticationInfo)
    ERROR(InvalidHeaderValue)
    ERROR(InvalidInput)
    ERROR(InvalidQueryParameterValue)
    ERROR(InvalidResourceName)
    ERROR(MissingRequiredHeader)
    ERROR(ResourceNotFound)
    ERROR(RequestNotSigned)
    ERROR(UnsupportedHttpVerb)
    ERROR(UnsupportedContentType)
    ERROR(RequestBodyTooLarge)
    ERROR(RequestHeaderTooLarge)
    ERROR(PreconditionFailed)

    // CCF-specific errors
    // client-facing:
    ERROR(SessionCapExhausted)
    ERROR(FrontendNotOpen)
    ERROR(KeyNotFound)
    ERROR(NodeAlreadyRecovering)
    ERROR(ProposalNotOpen)
    ERROR(ProposalNotFound)
    ERROR(ProposalFailedToValidate)
    ERROR(ServiceNotWaitingForRecoveryShares)
    ERROR(StateDigestMismatch)
    ERROR(TransactionNotFound)
    ERROR(TransactionCommitAttemptsExceedLimit)
    ERROR(TransactionReplicationFailed)
    ERROR(UnknownCertificate)
    ERROR(VoteNotFound)
    ERROR(VoteAlreadyExists)
    ERROR(NodeCannotHandleRequest)
    ERROR(TransactionPendingOrUnknown)
    ERROR(TransactionInvalid)
    ERROR(PrimaryNotFound)
    ERROR(BackupNotFound)
    ERROR(RequestAlreadyForwarded)
    ERROR(NodeNotRetiredCommitted)
    ERROR(SessionConsistencyLost)
    ERROR(ExecutorDispatchFailed)
    ERROR(ProposalReplay)
    ERROR(ProposalCreatedTooLongAgo)
    ERROR(InvalidCreatedAt)
    ERROR(JSException)
    ERROR(TooManyPendingTransactions)
    ERROR(MissingApiVersionParameter)
    ERROR(UnsupportedApiVersionValue)
    ERROR(EmptyFile)

    // node-to-node (/join and /create):
    ERROR(ConsensusTypeMismatch)
    ERROR(InvalidQuote)
    ERROR(InvalidNodeState)
    ERROR(NodeAlreadyExists)
    ERROR(StartupSeqnoIsOld)
    ERROR(CSRPublicKeyInvalid)

#undef ERROR
  }
}
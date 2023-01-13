// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/json.h"
#include "ccf/http_status.h"

namespace ccf
{
  struct ODataErrorDetails
  {
    std::string auth_policy;
    std::string code;
    std::string message;

    bool operator==(const ODataErrorDetails&) const = default;
  };

  DECLARE_JSON_TYPE(ODataErrorDetails);
  DECLARE_JSON_REQUIRED_FIELDS(ODataErrorDetails, auth_policy, code, message);

  struct ODataError
  {
    std::string code;
    std::string message;
    std::vector<ODataErrorDetails> details = {};
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
    http_status status;
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
    ERROR(RequestAlreadyForwarded)
    ERROR(NodeNotRetiredCommitted)
    ERROR(SessionConsistencyLost)
    ERROR(ExecutorDispatchFailed)
    ERROR(DuplicateOrStaleProposal)

    // node-to-node (/join and /create):
    ERROR(ConsensusTypeMismatch)
    ERROR(InvalidQuote)
    ERROR(InvalidNodeState)
    ERROR(NodeAlreadyExists)
    ERROR(StartupSeqnoIsOld)
    ERROR(CSRPublicKeyInvalid)

    ERROR(ResharingAlreadyCompleted)

#undef ERROR
  }
}
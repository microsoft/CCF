// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"
#include "http/http_status.h"

namespace ccf
{
  struct ODataError
  {
    std::string code;
    std::string message;
  };

  DECLARE_JSON_TYPE(ODataError);
  DECLARE_JSON_REQUIRED_FIELDS(ODataError, code, message);

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

    // See https://docs.microsoft.com/en-us/rest/api/storageservices/common-rest-api-error-codes
    // for inspiration.

    ERROR(InternalError)
    ERROR(AuthorizationFailed)
    ERROR(ConsensusTypeMismatch)
    ERROR(InvalidInput)
    ERROR(InvalidQuote)
    ERROR(InvalidNodeState)
    ERROR(InvalidResourceName)
    ERROR(NodeAlreadyExists)
    ERROR(ResourceNotFound)
    ERROR(ProposalNotOpen)
    ERROR(ProposalNotFound)
    ERROR(VoteNotFound)
    ERROR(KeyNotFound)
    ERROR(StateDigestMismatch)
    ERROR(RequestNotSigned)
    ERROR(VoteAlreadyExists)
    ERROR(UnknownCertificate)

    #undef ERROR
  }
}
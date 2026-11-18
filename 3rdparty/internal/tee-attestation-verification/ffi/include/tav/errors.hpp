// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Header-only exception helpers over the public C ABI in <tav/errors.h>.
//
// check() consumes an owned TavError* returned by a C ABI call and throws
// tav::Exception with its code and message, freeing the error first.
// A null pointer indicates success and does not throw.

#pragma once

#include <tav/errors.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace tav
{
/// Stable error codes returned by the native TAV ABI.
enum class ErrorCode : int
{
    OK = TAV_ERROR_OK,
    INVALID_ARGUMENT = TAV_ERROR_INVALID_ARGUMENT,
    IS_NULL = TAV_ERROR_IS_NULL,
    PANIC = TAV_ERROR_PANIC,

    SNP_UNSUPPORTED_PROCESSOR = TAV_ERROR_SNP_UNSUPPORTED_PROCESSOR,
    SNP_INVALID_ROOT_CERTIFICATE = TAV_ERROR_SNP_INVALID_ROOT_CERTIFICATE,
    SNP_CERTIFICATE_CHAIN_ERROR = TAV_ERROR_SNP_CERTIFICATE_CHAIN_ERROR,
    SNP_SIGNATURE_VERIFICATION_ERROR = TAV_ERROR_SNP_SIGNATURE_VERIFICATION_ERROR,
    SNP_TCB_VERIFICATION_ERROR = TAV_ERROR_SNP_TCB_VERIFICATION_ERROR,

    COSE_CBOR = TAV_ERROR_COSE_CBOR,
    COSE_UNEXPECTED_TYPE = TAV_ERROR_COSE_UNEXPECTED_TYPE,
    COSE_UNSUPPORTED_ALGORITHM = TAV_ERROR_COSE_UNSUPPORTED_ALGORITHM,
    COSE_KEY_IMPORT = TAV_ERROR_COSE_KEY_IMPORT,
    COSE_VERIFICATION = TAV_ERROR_COSE_VERIFICATION,

    CACI_COSE = TAV_ERROR_CACI_COSE,
    CACI_CERTIFICATE = TAV_ERROR_CACI_CERTIFICATE,
    CACI_DID_X509 = TAV_ERROR_CACI_DID_X509,
    CACI_SIGNATURE = TAV_ERROR_CACI_SIGNATURE,
    CACI_MEASUREMENT = TAV_ERROR_CACI_MEASUREMENT,
    CACI_POLICY = TAV_ERROR_CACI_POLICY,

    CBOR_DECODE_FAILED = TAV_ERROR_CBOR_DECODE_FAILED,
    CBOR_KEY_NOT_FOUND = TAV_ERROR_CBOR_KEY_NOT_FOUND,
    CBOR_OUT_OF_BOUND = TAV_ERROR_CBOR_OUT_OF_BOUND,
    CBOR_TYPE_MISMATCH = TAV_ERROR_CBOR_TYPE_MISMATCH,
    CBOR_ENCODE_FAILED = TAV_ERROR_CBOR_ENCODE_FAILED,
};

/// Thrown for every TavError the C ABI reports.
class Exception : public std::runtime_error
{
public:
    Exception(ErrorCode code, const std::string& what) :
      std::runtime_error(what),
      code_(code)
    {}

    [[nodiscard]] ErrorCode code() const
    {
        return code_;
    }

private:
    ErrorCode code_;
};

/// Consumes a TavError* a C ABI function returned: does nothing if null,
/// otherwise frees it and throws the equivalent Exception.
inline void check(TavError* error)
{
    if (error == nullptr)
    {
        return;
    }
    const std::unique_ptr<TavError, decltype(&tav_error_free)> owned(error, tav_error_free);
    const ErrorCode code = static_cast<ErrorCode>(tav_error_code(error));
    const std::string message = tav_error_message(error);
    throw Exception(code, message);
}
}

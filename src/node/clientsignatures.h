// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/hash.h"
#include "entities.h"

#include <mbedtls/md.h>
#include <msgpack/msgpack.hpp>
#include <vector>

MSGPACK_ADD_ENUM(mbedtls_md_type_t);

DECLARE_JSON_ENUM(
  mbedtls_md_type_t,
  {{MBEDTLS_MD_NONE, "MBEDTLS_MD_NONE"},
   {MBEDTLS_MD_SHA1, "MBEDTLS_MD_SHA1"},
   {MBEDTLS_MD_SHA256, "MBEDTLS_MD_SHA256"},
   {MBEDTLS_MD_SHA384, "MBEDTLS_MD_SHA384"},
   {MBEDTLS_MD_SHA512, "MBEDTLS_MD_SHA512"}});

namespace ccf
{
  struct SignedReq
  {
    // signature
    std::vector<uint8_t> sig = {};
    // the signed content
    std::vector<uint8_t> req = {};

    // the request body
    std::vector<uint8_t> request_body = {};

    // the hashing algorithm used
    mbedtls_md_type_t md = MBEDTLS_MD_NONE;

    bool operator==(const SignedReq& other) const
    {
      return (sig == other.sig) && (req == other.req) && (md == other.md) &&
        (request_body == other.request_body);
    }

    MSGPACK_DEFINE(sig, req, request_body, md);
  };
  DECLARE_JSON_TYPE(SignedReq)
  DECLARE_JSON_REQUIRED_FIELDS(SignedReq, sig, req, request_body, md)
  // this maps client-id to latest SignedReq
  using ClientSignatures = Store::Map<CallerId, SignedReq>;
}
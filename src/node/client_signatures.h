// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ds/hash.h"
#include "ds/json.h"
#include "entities.h"
#include "kv/map.h"
#include "crypto/hash.h"

#include <mbedtls/md.h>
#include <msgpack/msgpack.hpp>
#include <vector>

using namespace tls;
using namespace crypto;

MSGPACK_ADD_ENUM(MDType);

namespace crypto
{
  DECLARE_JSON_ENUM(
    MDType,
    {{MDType::NONE, "NONE"},
     {MDType::SHA1, "SHA1"},
     {MDType::SHA256, "SHA256"},
     {MDType::SHA384, "SHA384"},
     {MDType::SHA512, "SHA512"}});
}

namespace ccf
{
  struct SignedReq
  {
    // signature
    std::vector<uint8_t> sig = {};
    // signed content
    std::vector<uint8_t> req = {};

    // request body
    std::vector<uint8_t> request_body = {};

    // signature hashing algorithm used
    MDType md = MDType::NONE;

    // The key id, if declared in the request
    std::string key_id = {};

    bool operator==(const SignedReq& other) const
    {
      return (sig == other.sig) && (req == other.req) && (md == other.md) &&
        (request_body == other.request_body) && (key_id == other.key_id);
    }

    MSGPACK_DEFINE(sig, req, request_body, md);
  };
  DECLARE_JSON_TYPE(SignedReq)
  DECLARE_JSON_REQUIRED_FIELDS(SignedReq, sig, req, request_body, md, key_id)
  // this maps client-id to latest SignedReq
  using ClientSignatures = kv::Map<CallerId, SignedReq>;
}
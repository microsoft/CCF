// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "crypto/hash.h"
#include "ds/hash.h"
#include "ds/json.h"
#include "entities.h"
#include "service_map.h"

#include <mbedtls/md.h>
#include <vector>

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
    crypto::MDType md = crypto::MDType::NONE;

    // The key id, if declared in the request
    std::string key_id = {};

    bool operator==(const SignedReq& other) const
    {
      return (sig == other.sig) && (req == other.req) && (md == other.md) &&
        (request_body == other.request_body) && (key_id == other.key_id);
    }

    bool operator!=(const SignedReq& other) const
    {
      return !(*this == other);
    }
  };
  DECLARE_JSON_TYPE(SignedReq)
  DECLARE_JSON_REQUIRED_FIELDS(SignedReq, sig, req, request_body, md, key_id)
}
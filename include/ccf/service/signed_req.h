// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/md_type.h"
#include "ccf/ds/json.h"

#include <vector>

namespace ccf
{
  struct SignedReq
  {
    /// Signature
    std::vector<uint8_t> sig;

    /// Signed content
    std::vector<uint8_t> req;

    /// Request body
    std::vector<uint8_t> request_body;

    /// Hashing algorithm used to summarise content before signature
    ccf::crypto::MDType md = ccf::crypto::MDType::NONE;

    /// Signer key id, if present in the request
    std::string key_id;

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
  DECLARE_JSON_TYPE(SignedReq);
  DECLARE_JSON_REQUIRED_FIELDS(SignedReq, sig, req, request_body, md, key_id);
}

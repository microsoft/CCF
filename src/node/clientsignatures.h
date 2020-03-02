// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "../ds/hash.h"
#include "entities.h"
#include "rpc/jsonrpc.h"

#include <mbedtls/md.h>
#include <msgpack-c/msgpack.hpp>
#include <vector>

MSGPACK_ADD_ENUM(mbedtls_md_type_t);

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
  // this maps client-id to latest SignedReq
  using ClientSignatures = Store::Map<CallerId, SignedReq>;

  inline void to_json(nlohmann::json& j, const SignedReq& sr)
  {
    if (!sr.sig.empty())
    {
      j["sig"] = sr.sig;
    }
    if (!sr.req.empty())
    {
      j["req"] = nlohmann::json::from_msgpack(sr.req);
    }
    if (!sr.request_body.empty())
    {
      j["request_body"] = sr.request_body;
    }
  }

  inline void from_json(const nlohmann::json& j, SignedReq& sr)
  {
    auto sig_it = j.find("req");
    if (sig_it != j.end())
    {
      assign_j(sr.sig, j["sig"]);
    }
    auto req_it = j.find("req");
    if (req_it != j.end())
    {
      assign_j(sr.req, nlohmann::json::to_msgpack(req_it.value()));
    }
    auto raw_req_it = j.find("request_body");
    if (raw_req_it != j.end())
    {
      assign_j(sr.request_body, j["request_body"]);
    }
  }

  inline void fill_json_schema(nlohmann::json& j, const SignedReq& sr)
  {
    j["type"] = "object";

    j["properties"]["req"] = nlohmann::json();

    auto sig_schema = nlohmann::json::object();
    sig_schema["type"] = "array";
    sig_schema["items"] = ::ds::json::schema_element<uint8_t>();
    j["properties"]["sig"] = sig_schema;

    j["required"].push_back("req");
  }
}
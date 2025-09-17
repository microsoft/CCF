// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/ds/quote_info.h"
#include "ccf/kv/version.h"
#include "ds/actors.h"
#include "http/curl.h"

#include <curl/curl.h>
#include <llhttp/llhttp.h>
#include <sys/types.h>

namespace ccf::self_healing_open
{
  struct RequestNodeInfo
  {
    QuoteInfo quote_info;
    std::string published_network_address;
    std::string intrinsic_id;
    std::string service_identity;
  };
  DECLARE_JSON_TYPE(RequestNodeInfo);
  DECLARE_JSON_REQUIRED_FIELDS(
    RequestNodeInfo,
    quote_info,
    published_network_address,
    intrinsic_id,
    service_identity);

  struct GossipRequest
  {
    RequestNodeInfo info;
    ccf::kv::Version txid;
  };
  DECLARE_JSON_TYPE(GossipRequest);
  DECLARE_JSON_REQUIRED_FIELDS(GossipRequest, txid, info);

  struct VoteRequest
  {
    RequestNodeInfo info;
  };
  DECLARE_JSON_TYPE(VoteRequest);
  DECLARE_JSON_REQUIRED_FIELDS(VoteRequest, info);

  struct IAmOpenRequest
  {
    RequestNodeInfo info;
  };
  DECLARE_JSON_TYPE(IAmOpenRequest);
  DECLARE_JSON_REQUIRED_FIELDS(IAmOpenRequest, info);

}
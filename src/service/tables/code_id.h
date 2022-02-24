// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service/tables/code_digest.h"
#include "ccf/kv/serialisers/blit_serialiser_code_digest.h"
#include "ccf/service/map.h"

namespace ccf
{
  using CodeIDs = ServiceMap<CodeDigest, CodeStatus>;
  namespace Tables
  {
    static constexpr auto NODE_CODE_IDS = "public:ccf.gov.nodes.code_ids";
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "client_signatures.h"
#include "service_map.h"

namespace ccf
{
  using GovernanceHistory = ServiceMap<MemberId, SignedReq>;
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "resharing_types.h"
#include "service/map.h"

namespace ccf
{
  using Resharings = ServiceMap<kv::ReconfigurationId, ResharingResult>;
}
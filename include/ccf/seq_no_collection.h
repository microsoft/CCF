// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/contiguous_set.h"
#include "ccf/tx_id.h"

namespace ccf
{
  using SeqNoCollection = ccf::ds::ContiguousSet<ccf::SeqNo>;
}

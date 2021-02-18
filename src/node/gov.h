// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"

namespace ccf {
    namespace jsgov {
        using ProposalId = std::string;
        using Proposal = std::string;

        using ProposalMap = kv::RawCopySerialisedMap<ProposalId, Proposal>;
    }
}
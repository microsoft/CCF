// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/map.h"
#include "ds/json.h"
#include "entities.h"

namespace ccf {
    namespace jsgov {
        using ProposalId = std::string;
        using Proposal = std::string;
        struct ProposalInfo
        {
            ccf::MemberId proposer_id;
            std::unordered_map<ccf::MemberId, std::string> ballots = {};
        };
        DECLARE_JSON_TYPE(ProposalInfo)
        DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, proposer_id, ballots);

        using ProposalMap = kv::RawCopySerialisedMap<ProposalId, Proposal>;
        using ProposalInfoMap = kv::MapSerialisedWith<
            ProposalId,
            ProposalInfo,
            kv::serialisers::BlitSerialiser,
            kv::serialisers::JsonSerialiser>;
    }
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <nlohmann/json.hpp>
#include <vector>

namespace kv::serialisers
{
    using SerialisedEntry = std::vector<uint8_t>;
}
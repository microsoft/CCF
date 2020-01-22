// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <cstdint>
#include <map>
#include <thread>

extern std::map<std::thread::id, uint16_t> thread_ids;
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <cstdint>
#include <map>
#include <thread>

std::map<std::thread::id, uint16_t> thread_ids;
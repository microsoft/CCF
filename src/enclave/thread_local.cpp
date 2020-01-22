// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include <cstdint>
#include <thread>
#include <map>

std::map<std::thread::id, uint16_t> tls_thread_id;
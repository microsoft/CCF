// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <optional>
#include <string>

namespace ccf
{
  std::optional<std::string> v8_kv_module_load_callback(
    const std::string& module_name, void* opaque);
} // namespace ccf
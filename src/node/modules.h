// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "service_map.h"

#include <msgpack/msgpack.hpp>
#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

namespace ccf
{
  // struct Module
  // {
  //   std::string js;

  //   Module() = default;

  //   Module(const std::string& js_) : js(js_) {}

  //   MSGPACK_DEFINE(js);
  // };
  // DECLARE_JSON_TYPE(Module)
  // DECLARE_JSON_REQUIRED_FIELDS(Module, js)

  using Module = std::string;

  // ls_js_sgx_cft^/client_0: 1653.8537810682178
  // using Modules = kv::RawCopySerialisedMap<std::string, Module>;

  // TODO: Decide on serialisation format
  using Modules = ServiceMap<std::string, Module>;

}
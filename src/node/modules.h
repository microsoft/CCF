// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <msgpack/msgpack.hpp>
#include <optional>
#include <stdint.h>
#include <string>
#include <vector>

namespace ccf
{
  struct Module
  {
    std::optional<std::string> js;
    // std::optional<uint8_t> wasm;

    Module() = default;

    Module(const std::string& js_) :
      js(js_)
    {}

    MSGPACK_DEFINE(js);
  };
  DECLARE_JSON_TYPE_WITH_OPTIONAL_FIELDS(Module)
  
  // Current limitation of the JSON macros: It is necessary to defined
  // DECLARE_JSON_REQUIRED_FIELDS for Script even though there are no required
  // fields. This raises some compiler warnings that are disabled locally.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
  DECLARE_JSON_REQUIRED_FIELDS(Module)
#pragma clang diagnostic pop

  DECLARE_JSON_OPTIONAL_FIELDS(Module, js)

  using Modules = kv::Map<std::string, Module>;
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "kv/untyped_map.h"

#include <map>
#include <string>
#include <v8.h>

namespace ccf::v8_tmpl
{
  using KVMapType = kv::untyped::Map;
  using KVMapHandle = KVMapType::Handle;
  using KVMapReadOnlyHandle = KVMapType::ReadOnlyHandle;

  class KVMapReadOnly
  {
  public:
    static constexpr const char* NAME = "CCFKVMapReadOnly";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, KVMapReadOnlyHandle* map_handle);
  };

  class KVMapReadWrite
  {
  public:
    static constexpr const char* NAME = "CCFKVMapReadWrite";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, KVMapHandle* map_handle);
  };

} // namespace ccf::v8_tmpl

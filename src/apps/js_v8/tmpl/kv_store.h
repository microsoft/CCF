// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "v8.h"
#include "ccf/tx.h"
#include "kv_map.h"
#include <string>
#include <map>

namespace ccf::v8_tmpl
{
  enum class TxAccess
  {
    APP,
    GOV_RO,
    GOV_RW
  };

  struct TxContext
  {
    kv::Tx* tx = nullptr;
    TxAccess access = TxAccess::APP;
  };

  class KVStore
  {
  public:
    static constexpr const char* NAME = "CCFKVStore";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(v8::Local<v8::Context> context, TxContext& tx_ctx);
  };

} // namespace ccf::v8_tmpl

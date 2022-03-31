// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/tx.h"
#include "kv_map.h"

#include <map>
#include <string>
#include <v8.h>

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

  class KVStoreReadWrite
  {
  public:
    static constexpr const char* NAME = "CCFKVStoreReadWrite";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, TxContext* tx_ctx);
  };

  struct ReadOnlyTxContext
  {
    kv::ReadOnlyTx* tx = nullptr;
    TxAccess access = TxAccess::APP;
  };

  class KVStoreReadOnly
  {
  public:
    static constexpr const char* NAME = "CCFKVStoreReadOnly";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, ReadOnlyTxContext* tx_ctx);
  };

} // namespace ccf::v8_tmpl

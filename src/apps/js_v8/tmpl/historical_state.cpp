// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "template.h"
#include "historical_state.h"
#include "kv_store.h"
#include "receipt.h"

namespace ccf::v8_tmpl
{
  struct HistoricalStateContext
  {
    ccf::historical::State* state;
    kv::CommittableTx tx;
    TxContext tx_ctx;
  };

  static HistoricalStateContext* unwrap_historical_state_ctx(v8::Local<v8::Object> obj)
  {
    return static_cast<HistoricalStateContext*>(obj->GetAlignedPointerFromInternalField(0));
  }

  static void get_kv_store(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    HistoricalStateContext* state_ctx = unwrap_historical_state_ctx(info.Holder());

    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    
    v8::Local<v8::Value> value = KVStore::wrap(context, state_ctx->tx_ctx);
    info.GetReturnValue().Set(value);
  }

  static void get_tx_id(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    HistoricalStateContext* state_ctx = unwrap_historical_state_ctx(info.Holder());

    std::string txid = state_ctx->state->transaction_id.to_str();
    v8::Local<v8::String> value = v8_util::to_v8_str(info.GetIsolate(), txid);

    info.GetReturnValue().Set(value);
  }

  static void get_receipt(v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    HistoricalStateContext* state_ctx = unwrap_historical_state_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();
    
    v8::Local<v8::Value> value = Receipt::wrap(context, state_ctx->state->receipt.get());
    info.GetReturnValue().Set(value);
  }

  v8::Local<v8::ObjectTemplate> HistoricalState::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);
    
    // Field 0: HistoricalStateContext
    tmpl->SetInternalFieldCount(1);

    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "kv"),
      get_kv_store);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "transactionId"),
      get_tx_id);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "receipt"),
      get_receipt);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> HistoricalState::wrap(v8::Local<v8::Context> context, ccf::historical::State* historical_state)
  {
    auto state_ctx = new HistoricalStateContext{
      historical_state, historical_state->store->create_tx(), TxContext{nullptr, TxAccess::APP}};
    state_ctx->tx_ctx.tx = &state_ctx->tx;
    V8Context::from_context(context).register_finalizer([](void* data) {
      delete static_cast<HistoricalStateContext*>(data);
    }, state_ctx);

    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = get_cached_object_template<HistoricalState>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();
    result->SetAlignedPointerInInternalField(0, state_ctx);

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl

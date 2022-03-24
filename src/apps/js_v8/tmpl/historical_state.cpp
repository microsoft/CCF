// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "historical_state.h"

#include "ccf/ds/logger.h"
#include "kv_store.h"
#include "receipt.h"
#include "template.h"

namespace ccf::v8_tmpl
{
  struct HistoricalStateContext
  {
    ccf::historical::StatePtr state;
    kv::ReadOnlyTx tx;
    ReadOnlyTxContext tx_ctx;
  };

  enum class InternalField
  {
    HistoricalStateContext,
    END
  };

  static HistoricalStateContext* unwrap_historical_state_ctx(
    v8::Local<v8::Object> obj)
  {
    return static_cast<HistoricalStateContext*>(
      get_internal_field(obj, InternalField::HistoricalStateContext));
  }

  static void get_kv_store(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    HistoricalStateContext* state_ctx =
      unwrap_historical_state_ctx(info.Holder());

    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value =
      KVStoreReadOnly::wrap(context, &state_ctx->tx_ctx);
    info.GetReturnValue().Set(value);
  }

  static void get_tx_id(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    HistoricalStateContext* state_ctx =
      unwrap_historical_state_ctx(info.Holder());

    std::string txid = state_ctx->state->transaction_id.to_str();
    v8::Local<v8::String> value = v8_util::to_v8_str(info.GetIsolate(), txid);

    info.GetReturnValue().Set(value);
  }

  static void get_receipt(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    HistoricalStateContext* state_ctx =
      unwrap_historical_state_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value =
      Receipt::wrap(context, *state_ctx->state->receipt);
    info.GetReturnValue().Set(value);
  }

  v8::Local<v8::ObjectTemplate> HistoricalState::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "kv"), get_kv_store);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "transactionId"), get_tx_id);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "receipt"), get_receipt);

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> HistoricalState::wrap(
    v8::Local<v8::Context> context,
    const ccf::historical::StatePtr& historical_state)
  {
    auto state_ctx = new HistoricalStateContext{
      historical_state,
      historical_state->store->create_read_only_tx(),
      ReadOnlyTxContext{nullptr, TxAccess::APP}};
    state_ctx->tx_ctx.tx = &state_ctx->tx;
    V8Context::from_context(context).register_finalizer(
      [](void* data) { delete static_cast<HistoricalStateContext*>(data); },
      state_ctx);

    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<HistoricalState>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result, {{{InternalField::HistoricalStateContext, state_ctx}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl

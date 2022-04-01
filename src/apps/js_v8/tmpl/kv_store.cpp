// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "kv_store.h"

#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    TxContext,
    END
  };

  static TxContext* unwrap_tx_ctx(v8::Local<v8::Object> obj)
  {
    return static_cast<TxContext*>(
      get_internal_field(obj, InternalField::TxContext));
  }

  static ReadOnlyTxContext* unwrap_read_only_tx_ctx(v8::Local<v8::Object> obj)
  {
    return static_cast<ReadOnlyTxContext*>(
      get_internal_field(obj, InternalField::TxContext));
  }

  static void js_kv_lookup(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    if (name->IsSymbol())
      return;

    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    TxContext* tx_ctx_ptr = unwrap_tx_ctx(info.Holder());
    std::string property_name = v8_util::to_str(isolate, name.As<v8::String>());

    const auto [security_domain, access_category] =
      kv::parse_map_name(property_name);

    auto read_only = false;
    switch (access_category)
    {
      case kv::AccessCategory::INTERNAL:
      {
        if (security_domain == kv::SecurityDomain::PUBLIC)
        {
          read_only = true;
        }
        else
        {
          v8_util::throw_error(
            isolate,
            fmt::format(
              "JS application cannot access private internal CCF table '{}'",
              property_name));
          return;
        }
        break;
      }
      case kv::AccessCategory::GOVERNANCE:
      {
        read_only = tx_ctx_ptr->access != TxAccess::GOV_RW;
        break;
      }
      case kv::AccessCategory::APPLICATION:
      {
        read_only = tx_ctx_ptr->access != TxAccess::APP;
        break;
      }
      default:
      {
        v8_util::throw_error(
          isolate,
          fmt::format(
            "Unhandled AccessCategory for table '{}'", property_name));
        return;
      }
    }

    auto handle = tx_ctx_ptr->tx->rw<KVMapType>(property_name);
    v8::Local<v8::Value> value;
    if (read_only)
    {
      value = KVMapReadOnly::wrap(context, handle);
    }
    else
    {
      value = KVMapReadWrite::wrap(context, handle);
    }

    info.GetReturnValue().Set(value);
  }

  static void js_read_only_kv_lookup(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    if (name->IsSymbol())
      return;

    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    ReadOnlyTxContext* tx_ctx_ptr = unwrap_read_only_tx_ctx(info.Holder());
    std::string property_name = v8_util::to_str(isolate, name.As<v8::String>());

    auto handle = tx_ctx_ptr->tx->ro<KVMapType>(property_name);
    v8::Local<v8::Value> value;
    value = KVMapReadOnly::wrap(context, handle);

    info.GetReturnValue().Set(value);
  }

  v8::Local<v8::ObjectTemplate> KVStoreReadWrite::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->SetHandler(v8::NamedPropertyHandlerConfiguration(js_kv_lookup));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> KVStoreReadWrite::wrap(
    v8::Local<v8::Context> context, TxContext* tx_ctx)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<KVStoreReadWrite>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result, {{{InternalField::TxContext, tx_ctx}}});

    return handle_scope.Escape(result);
  }

  v8::Local<v8::ObjectTemplate> KVStoreReadOnly::create_template(
    v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->SetHandler(
      v8::NamedPropertyHandlerConfiguration(js_read_only_kv_lookup));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> KVStoreReadOnly::wrap(
    v8::Local<v8::Context> context, ReadOnlyTxContext* tx_ctx)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<KVStoreReadOnly>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result, {{{InternalField::TxContext, tx_ctx}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl

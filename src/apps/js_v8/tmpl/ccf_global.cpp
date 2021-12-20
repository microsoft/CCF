// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf_global.h"

#include "consensus.h"
#include "crypto.h"
#include "crypto/entropy.h"
#include "crypto/rsa_key_pair.h"
#include "ds/logger.h"
#include "historical.h"
#include "historical_state.h"
#include "kv_store.h"
#include "rpc.h"
#include "template.h"

namespace ccf::v8_tmpl
{
  enum class InternalField
  {
    TxContext,
    HistoricalStatePtr,
    EndpointRegistry,
    StateCache,
    RpcContext,
    END
  };

  static TxContext* unwrap_tx_ctx(v8::Local<v8::Object> obj)
  {
    return static_cast<TxContext*>(
      get_internal_field(obj, InternalField::TxContext));
  }

  static ccf::historical::StatePtr* unwrap_historical_state(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::historical::StatePtr*>(
      get_internal_field(obj, InternalField::HistoricalStatePtr));
  }

  static ccf::BaseEndpointRegistry* unwrap_endpoint_registry(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::BaseEndpointRegistry*>(
      get_internal_field(obj, InternalField::EndpointRegistry));
  }

  static ccf::historical::AbstractStateCache* unwrap_state_cache(
    v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::historical::AbstractStateCache*>(
      get_internal_field(obj, InternalField::StateCache));
  }

  static enclave::RpcContext* unwrap_rpc_context(v8::Local<v8::Object> obj)
  {
    return static_cast<enclave::RpcContext*>(
      get_internal_field(obj, InternalField::RpcContext));
  }

  static v8::Local<v8::ArrayBuffer> js_str_to_buf_direct(
    v8::Isolate* isolate, v8::Local<v8::String> str)
  {
    size_t buf_size = str->Utf8Length(isolate);

    std::unique_ptr<v8::BackingStore> store =
      v8::ArrayBuffer::NewBackingStore(isolate, buf_size);
    str->WriteUtf8(
      isolate,
      static_cast<char*>(store->Data()),
      buf_size,
      nullptr,
      v8::String::NO_NULL_TERMINATION);

    v8::Local<v8::ArrayBuffer> buffer =
      v8::ArrayBuffer::New(isolate, std::move(store));
    return buffer;
  }

  static void js_str_to_buf(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsString())
    {
      v8_util::throw_type_error(isolate, "Argument must be a string");
      return;
    }
    v8::Local<v8::String> str = arg.As<v8::String>();
    v8::Local<v8::ArrayBuffer> buffer = js_str_to_buf_direct(isolate, str);
    info.GetReturnValue().Set(buffer);
  }

  static v8::MaybeLocal<v8::String> js_buf_to_str_direct(
    v8::Isolate* isolate, v8::Local<v8::ArrayBuffer> buffer)
  {
    return v8::String::NewFromUtf8(
      isolate,
      static_cast<const char*>(buffer->GetBackingStore()->Data()),
      v8::NewStringType::kNormal,
      buffer->ByteLength());
  }

  static void js_buf_to_str(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg.As<v8::ArrayBuffer>();

    v8::Local<v8::String> str;
    if (!js_buf_to_str_direct(isolate, buffer).ToLocal(&str))
      return;
    info.GetReturnValue().Set(str);
  }

  static void js_json_compatible_to_buf(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    v8::Local<v8::String> json;
    if (!v8::JSON::Stringify(context, arg).ToLocal(&json))
      return;
    v8::Local<v8::ArrayBuffer> buffer = js_str_to_buf_direct(isolate, json);
    info.GetReturnValue().Set(buffer);
  }

  static void js_buf_to_json_compatible(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg = info[0];
    if (!arg->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg.As<v8::ArrayBuffer>();

    v8::Local<v8::String> str;
    if (!js_buf_to_str_direct(isolate, buffer).ToLocal(&str))
      return;

    v8::Local<v8::Value> parsed;
    if (!v8::JSON::Parse(context, str).ToLocal(&parsed))
      return;
    info.GetReturnValue().Set(parsed);
  }

  static void js_digest(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    if (info.Length() != 2)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 2", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg1 = info[0];
    if (!arg1->IsString())
    {
      v8_util::throw_type_error(isolate, "Argument 1 must be a string");
      return;
    }
    v8::Local<v8::String> digest_algo_name_v8 = arg1.As<v8::String>();
    std::string digest_algo_name =
      v8_util::to_str(isolate, digest_algo_name_v8);

    v8::Local<v8::Value> arg2 = info[1];
    if (!arg2->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument 2 must be an ArrayBuffer");
      return;
    }
    v8::Local<v8::ArrayBuffer> buffer = arg2.As<v8::ArrayBuffer>();

    if (digest_algo_name != "SHA-256")
    {
      v8_util::throw_range_error(
        isolate, "unsupported digest algorithm, supported: SHA-256");
      return;
    }

    auto data = v8_util::get_array_buffer_data(buffer);
    auto h = crypto::SHA256(data.p, data.n);
    v8::Local<v8::Value> value =
      v8_util::to_v8_array_buffer_copy(isolate, h.data(), h.size());

    info.GetReturnValue().Set(value);
  }

  static void js_generate_aes_key(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    if (info.Length() != 1)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1", info.Length()));
      return;
    }
    v8::Local<v8::Value> arg1 = info[0];
    int32_t key_size;
    if (!arg1->Int32Value(context).To(&key_size))
    {
      v8_util::throw_type_error(isolate, "Argument 1 must be a number");
      return;
    }

    // Supported key sizes for AES.
    if (key_size != 128 && key_size != 192 && key_size != 256)
    {
      v8_util::throw_range_error(
        isolate, "unsupported key size, supported: 128, 192, 256");
      return;
    }

    std::vector<uint8_t> key = crypto::create_entropy()->random(key_size / 8);

    v8::Local<v8::Value> value =
      v8_util::to_v8_array_buffer_copy(isolate, key.data(), key.size());

    info.GetReturnValue().Set(value);
  }

  static void js_generate_rsa_key_pair(
    const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();
    if (info.Length() != 1 && info.Length() != 2)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 1 or 2", info.Length()));
      return;
    }

    uint32_t key_size = 0;
    uint32_t key_exponent = 0;

    if (!info[0]->Uint32Value(context).To(&key_size))
    {
      v8_util::throw_type_error(isolate, "Argument 1 must be a number");
      return;
    }

    if (info.Length() == 2)
    {
      if (!info[1]->Uint32Value(context).To(&key_exponent))
      {
        v8_util::throw_type_error(isolate, "Argument 2 must be a number");
        return;
      }
    }


    std::shared_ptr<crypto::RSAKeyPair> k;
    if (info.Length() == 1)
    {
      k = crypto::make_rsa_key_pair(key_size);
    }
    else
    {
      k = crypto::make_rsa_key_pair(key_size, key_exponent);
    }

    crypto::Pem prv = k->private_key_pem();
    crypto::Pem pub = k->public_key_pem();

    v8::Local<v8::Object> value = v8::Object::New(isolate);
    value->Set(context,
      v8_util::to_v8_str(isolate, "privateKey"),
      v8_util::to_v8_str(isolate, prv.str()));
    value->Set(context,
      v8_util::to_v8_str(isolate, "publicKey"),
      v8_util::to_v8_str(isolate, pub.str()));

    info.GetReturnValue().Set(value);
  }

  static void get_kv_store(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    TxContext* tx_ctx = unwrap_tx_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value = KVStore::wrap(context, tx_ctx);
    info.GetReturnValue().Set(value);
  }

  static void get_historical_state(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::historical::StatePtr* historical_state =
      unwrap_historical_state(info.Holder());
    if (*historical_state == nullptr)
    {
      info.GetReturnValue().Set(v8::Undefined(info.GetIsolate()));
      return;
    }
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value =
      HistoricalState::wrap(context, *historical_state);
    info.GetReturnValue().Set(value);
  }

  static void get_consensus(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::BaseEndpointRegistry* endpoint_registry =
      unwrap_endpoint_registry(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value = Consensus::wrap(context, endpoint_registry);
    info.GetReturnValue().Set(value);
  }

  static void get_historical(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    ccf::historical::AbstractStateCache* state_cache =
      unwrap_state_cache(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value = Historical::wrap(context, state_cache);
    info.GetReturnValue().Set(value);
  }

  static void get_rpc(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    enclave::RpcContext* rpc_ctx = unwrap_rpc_context(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value = Rpc::wrap(context, rpc_ctx);
    info.GetReturnValue().Set(value);
  }

  static void get_crypto(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value = Crypto::wrap(context);
    info.GetReturnValue().Set(value);
  }

  v8::Local<v8::ObjectTemplate> CCFGlobal::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    set_internal_field_count<InternalField>(tmpl);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "strToBuf"),
      v8::FunctionTemplate::New(isolate, js_str_to_buf));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "bufToStr"),
      v8::FunctionTemplate::New(isolate, js_buf_to_str));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "jsonCompatibleToBuf"),
      v8::FunctionTemplate::New(isolate, js_json_compatible_to_buf));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "bufToJsonCompatible"),
      v8::FunctionTemplate::New(isolate, js_buf_to_json_compatible));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "digest"),
      v8::FunctionTemplate::New(isolate, js_digest));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "generateAesKey"),
      v8::FunctionTemplate::New(isolate, js_generate_aes_key));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "generateRsaKeyPair"),
      v8::FunctionTemplate::New(isolate, js_generate_rsa_key_pair));
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "kv"), get_kv_store);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "historicalState"), get_historical_state);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "consensus"), get_consensus);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "historical"), get_historical);
    tmpl->SetLazyDataProperty(v8_util::to_v8_istr(isolate, "rpc"), get_rpc);
    tmpl->SetLazyDataProperty(
      v8_util::to_v8_istr(isolate, "crypto"), get_crypto);

    // To be wrapped:
    // ccf.host
    // ccf.isValidX509CertBundle()
    // ccf.isValidX509CertChain()
    // ccf.wrapKey()

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> CCFGlobal::wrap(
    v8::Local<v8::Context> context,
    TxContext* tx_ctx,
    ccf::historical::StatePtr* historical_state,
    ccf::BaseEndpointRegistry* endpoint_registry,
    ccf::historical::AbstractStateCache* state_cache,
    enclave::RpcContext* rpc_ctx)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<CCFGlobal>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    set_internal_fields<InternalField>(
      result,
      {{{InternalField::TxContext, tx_ctx},
        {InternalField::HistoricalStatePtr, historical_state},
        {InternalField::EndpointRegistry, endpoint_registry},
        {InternalField::StateCache, state_cache},
        {InternalField::RpcContext, rpc_ctx}}});

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl

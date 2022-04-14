// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf_global.h"

#include "apps/js_v8/tmpl/crypto.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/sha256.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "consensus.h"
#include "historical.h"
#include "historical_state.h"
#include "kv_store.h"
#include "rpc.h"
#include "template.h"
#include "tls/ca.h"

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

  static ccf::RpcContext* unwrap_rpc_context(v8::Local<v8::Object> obj)
  {
    return static_cast<ccf::RpcContext*>(
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
    auto h = crypto::sha256(data.data(), data.size());
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
    value
      ->Set(
        context,
        v8_util::to_v8_str(isolate, "privateKey"),
        v8_util::to_v8_str(isolate, prv.str()))
      .Check();
    value
      ->Set(
        context,
        v8_util::to_v8_str(isolate, "publicKey"),
        v8_util::to_v8_str(isolate, pub.str()))
      .Check();

    info.GetReturnValue().Set(value);
  }

  static void js_is_valid_x509_cert_bundle(
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
    if (!arg1->IsString())
    {
      v8_util::throw_type_error(isolate, "Argument 1 must be a string");
      return;
    }
    std::string pem = v8_util::to_str(isolate, arg1.As<v8::String>());

    bool valid = false;
    try
    {
      tls::CA ca(pem);
      valid = true;
    }
    catch (const std::logic_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Bundle: {}", e.what());
    }

    info.GetReturnValue().Set(v8::Boolean::New(isolate, valid));
  }

  static std::vector<crypto::Pem> split_x509_cert_bundle(
    const std::string_view& pem)
  {
    std::string separator("-----END CERTIFICATE-----");
    std::vector<crypto::Pem> pems;
    auto separator_end = 0;
    auto next_separator_start = pem.find(separator);
    while (next_separator_start != std::string_view::npos)
    {
      pems.emplace_back(std::string(
        pem.substr(separator_end, next_separator_start + separator.size())));
      separator_end = next_separator_start + separator.size();
      next_separator_start = pem.find(separator, separator_end);
    }
    return pems;
  }

  static void js_is_valid_x509_cert_chain(
    const v8::FunctionCallbackInfo<v8::Value>& info)
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
    v8::Local<v8::Value> arg2 = info[1];
    if (!arg1->IsString() || !arg2->IsString())
    {
      v8_util::throw_type_error(isolate, "Arguments 1 and 2 must be strings");
      return;
    }
    std::string chain = v8_util::to_str(isolate, arg1.As<v8::String>());
    std::string trusted = v8_util::to_str(isolate, arg2.As<v8::String>());

    bool valid = false;

    try
    {
      auto chain_vec = split_x509_cert_bundle(chain);
      auto trusted_vec = split_x509_cert_bundle(trusted);
      if (chain_vec.empty() || trusted_vec.empty())
        throw std::logic_error(
          "chain/trusted arguments must contain at least one certificate");

      auto& target_pem = chain_vec[0];
      std::vector<const crypto::Pem*> chain_ptr;
      for (auto it = chain_vec.begin() + 1; it != chain_vec.end(); it++)
        chain_ptr.push_back(&*it);
      std::vector<const crypto::Pem*> trusted_ptr;
      for (auto& pem : trusted_vec)
        trusted_ptr.push_back(&pem);

      auto verifier = crypto::make_unique_verifier(target_pem);
      if (!verifier->verify_certificate(trusted_ptr, chain_ptr))
        throw std::logic_error("certificate chain is invalid");

      valid = true;
    }
    catch (const std::logic_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Chain: {}", e.what());
    }

    info.GetReturnValue().Set(v8::Boolean::New(isolate, valid));
  }

  static void js_wrap_key(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    if (info.Length() != 3)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 3", info.Length()));
      return;
    }

    // API loosely modeled after
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey.

    v8::Local<v8::Value> arg_key = info[0];
    if (!arg_key->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument 1 must be an ArrayBuffer");
      return;
    }
    auto key = v8_util::get_array_buffer_data(arg_key.As<v8::ArrayBuffer>());

    v8::Local<v8::Value> arg_wrapping_key = info[1];
    if (!arg_wrapping_key->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument 2 must be an ArrayBuffer");
      return;
    }
    auto wrapping_key =
      v8_util::get_array_buffer_data(arg_wrapping_key.As<v8::ArrayBuffer>());

    v8::Local<v8::Value> arg_parameters = info[2];
    if (!arg_parameters->IsObject())
    {
      v8_util::throw_type_error(isolate, "Argument 3 must be an object");
      return;
    }
    v8::Local<v8::Object> parameters_obj = arg_parameters.As<v8::Object>();

    v8::Local<v8::Value> algo_name_val;
    if (
      !parameters_obj->Get(context, v8_util::to_v8_istr(isolate, "name"))
         .ToLocal(&algo_name_val) ||
      !algo_name_val->IsString())
    {
      v8_util::throw_type_error(
        isolate, "Argument 3 must have a 'name' property that is a string");
      return;
    }
    auto algo_name = v8_util::to_str(isolate, algo_name_val.As<v8::String>());

    try
    {
      if (algo_name == "RSA-OAEP")
      {
        // key can in principle be arbitrary data (see note on maximum size
        // in rsa_key_pair.h). wrapping_key is a public RSA key.

        v8::Local<v8::Value> label_val;
        std::span<uint8_t> label;
        if (parameters_obj->Get(context, v8_util::to_v8_istr(isolate, "label"))
              .ToLocal(&label_val))
        {
          if (!label_val->IsArrayBuffer())
          {
            v8_util::throw_type_error(
              isolate,
              "'label' property of argument 3, if existing, must be an "
              "ArrayBuffer");
            return;
          }
          label =
            v8_util::get_array_buffer_data(label_val.As<v8::ArrayBuffer>());
        }

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (!label.empty())
        {
          label_opt = {label.begin(), label.end()};
        }

        auto wrapped_key = crypto::ckm_rsa_pkcs_oaep_wrap(
          crypto::Pem(wrapping_key),
          {key.data(), key.data() + key.size()},
          label_opt);

        info.GetReturnValue().Set(v8_util::to_v8_array_buffer_copy(
          isolate, wrapped_key.data(), wrapped_key.size()));
        return;
      }
      else if (algo_name == "AES-KWP")
      {
        std::vector<uint8_t> wrapped_key = crypto::ckm_aes_key_wrap_pad(
          {wrapping_key.data(), wrapping_key.data() + wrapping_key.size()},
          {key.data(), key.data() + key.size()});

        info.GetReturnValue().Set(v8_util::to_v8_array_buffer_copy(
          isolate, wrapped_key.data(), wrapped_key.size()));
        return;
      }
      else if (algo_name == "RSA-OAEP-AES-KWP")
      {
        v8::Local<v8::Value> aes_key_size_val;
        int32_t aes_key_size;
        if (
          !parameters_obj
             ->Get(context, v8_util::to_v8_istr(isolate, "aesKeySize"))
             .ToLocal(&aes_key_size_val) ||
          !aes_key_size_val->Int32Value(context).To(&aes_key_size))
        {
          v8_util::throw_type_error(
            isolate,
            "Argument 3 must have an 'aesKeySize' property that is a number");
          return;
        }

        v8::Local<v8::Value> label_val;
        std::span<uint8_t> label;
        if (parameters_obj->Get(context, v8_util::to_v8_istr(isolate, "label"))
              .ToLocal(&label_val))
        {
          if (!label_val->IsArrayBuffer())
          {
            v8_util::throw_type_error(
              isolate,
              "'label' property of argument 3, if existing, must be an "
              "ArrayBuffer");
            return;
          }
          label =
            v8_util::get_array_buffer_data(label_val.As<v8::ArrayBuffer>());
        }

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (!label.empty())
        {
          label_opt = {label.data(), label.data() + label.size()};
        }

        auto wrapped_key = crypto::ckm_rsa_aes_key_wrap(
          aes_key_size,
          crypto::Pem(wrapping_key),
          {key.data(), key.data() + key.size()},
          label_opt);

        info.GetReturnValue().Set(v8_util::to_v8_array_buffer_copy(
          isolate, wrapped_key.data(), wrapped_key.size()));
      }
      else
      {
        v8_util::throw_range_error(
          isolate,
          "Argument 3 must have a 'name' property that is one of 'RSA-OAEP', "
          "'AES-KWP', or 'RSA-OAEP-AES-KWP'");
        return;
      }
    }
    catch (std::exception& ex)
    {
      v8_util::throw_range_error(isolate, ex.what());
    }
  }

  static void get_kv_store(
    v8::Local<v8::Name> name, const v8::PropertyCallbackInfo<v8::Value>& info)
  {
    TxContext* tx_ctx = unwrap_tx_ctx(info.Holder());
    v8::Local<v8::Context> context = info.GetIsolate()->GetCurrentContext();

    v8::Local<v8::Value> value = KVStoreReadWrite::wrap(context, tx_ctx);
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
    ccf::RpcContext* rpc_ctx = unwrap_rpc_context(info.Holder());
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
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "isValidX509CertBundle"),
      v8::FunctionTemplate::New(isolate, js_is_valid_x509_cert_bundle));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "isValidX509CertChain"),
      v8::FunctionTemplate::New(isolate, js_is_valid_x509_cert_chain));
    tmpl->Set(
      v8_util::to_v8_istr(isolate, "wrapKey"),
      v8::FunctionTemplate::New(isolate, js_wrap_key));
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

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> CCFGlobal::wrap(
    v8::Local<v8::Context> context,
    TxContext* tx_ctx,
    ccf::historical::StatePtr* historical_state,
    ccf::BaseEndpointRegistry* endpoint_registry,
    ccf::historical::AbstractStateCache* state_cache,
    ccf::RpcContext* rpc_ctx)
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

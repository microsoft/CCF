// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "apps/js_v8/tmpl/crypto.h"

#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/logger.h"
#include "crypto/ecdsa.h"
#include "template.h"

// NOTE: The rest of the crypto functions are defined in ccf_global.cpp.

namespace ccf::v8_tmpl
{
  static void verify_signature(const v8::FunctionCallbackInfo<v8::Value>& info)
  {
    v8::Isolate* isolate = info.GetIsolate();
    v8::Local<v8::Context> context = isolate->GetCurrentContext();

    if (info.Length() != 4)
    {
      v8_util::throw_type_error(
        isolate,
        fmt::format("Passed {} arguments, but expected 4", info.Length()));
      return;
    }

    // API loosely modeled after
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify.

    v8::Local<v8::Value> arg_algo = info[0];
    if (!arg_algo->IsObject())
    {
      v8_util::throw_type_error(isolate, "Argument 1 must be an object");
      return;
    }

    v8::Local<v8::Object> algo_obj = arg_algo.As<v8::Object>();
    v8::Local<v8::Value> algo_name_val;
    if (
      !algo_obj->Get(context, v8_util::to_v8_istr(isolate, "name"))
         .ToLocal(&algo_name_val) ||
      !algo_name_val->IsString())
    {
      v8_util::throw_type_error(
        isolate, "Argument 1 must have a 'name' property that is a string");
      return;
    }
    auto algo_name = v8_util::to_str(isolate, algo_name_val.As<v8::String>());

    v8::Local<v8::Value> algo_hash_val;
    if (
      !algo_obj->Get(context, v8_util::to_v8_istr(isolate, "hash"))
         .ToLocal(&algo_hash_val) ||
      !algo_hash_val->IsString())
    {
      v8_util::throw_type_error(
        isolate, "Argument 1 must have a 'hash' property that is a string");
      return;
    }
    auto algo_hash = v8_util::to_str(isolate, algo_hash_val.As<v8::String>());

    v8::Local<v8::Value> arg_key = info[1];
    if (!arg_key->IsString())
    {
      v8_util::throw_type_error(isolate, "Argument 2 must be a string");
      return;
    }
    auto key = v8_util::to_str(isolate, arg_key.As<v8::String>());

    v8::Local<v8::Value> arg_sig = info[2];
    if (!arg_sig->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument 3 must be an ArrayBuffer");
      return;
    }
    auto signature =
      v8_util::get_array_buffer_data(arg_sig.As<v8::ArrayBuffer>());

    v8::Local<v8::Value> arg_data = info[3];
    if (!arg_data->IsArrayBuffer())
    {
      v8_util::throw_type_error(isolate, "Argument 4 must be an ArrayBuffer");
      return;
    }
    auto data = v8_util::get_array_buffer_data(arg_data.As<v8::ArrayBuffer>());

    try
    {
      crypto::MDType mdtype;
      if (algo_hash == "SHA-256")
      {
        mdtype = crypto::MDType::SHA256;
      }
      else
      {
        v8_util::throw_range_error(
          isolate, "Unsupported hash algorithm, supported: SHA-256");
        return;
      }

      if (algo_name != "RSASSA-PKCS1-v1_5" && algo_name != "ECDSA")
      {
        v8_util::throw_range_error(
          isolate,
          "Unsupported signing algorithm, supported: RSASSA-PKCS1-v1_5, "
          "ECDSA");
        return;
      }

      std::vector<uint8_t> sig(
        signature.data(), signature.data() + signature.size());

      if (algo_name == "ECDSA")
      {
        sig = crypto::ecdsa_sig_p1363_to_der(sig);
      }

      auto is_cert = nonstd::starts_with(key, "-----BEGIN CERTIFICATE");

      bool valid = false;

      if (is_cert)
      {
        auto verifier = crypto::make_unique_verifier(key);
        valid = verifier->verify(
          data.data(), data.size(), sig.data(), sig.size(), mdtype);
      }
      else
      {
        auto public_key = crypto::make_public_key(key);
        valid = public_key->verify(
          data.data(), data.size(), sig.data(), sig.size(), mdtype);
      }

      info.GetReturnValue().Set(v8::Boolean::New(isolate, valid));
    }
    catch (std::exception& ex)
    {
      v8_util::throw_range_error(isolate, ex.what());
    }
  }

  v8::Local<v8::ObjectTemplate> Crypto::create_template(v8::Isolate* isolate)
  {
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl = v8::ObjectTemplate::New(isolate);

    tmpl->Set(
      v8_util::to_v8_istr(isolate, "verifySignature"),
      v8::FunctionTemplate::New(isolate, verify_signature));

    return handle_scope.Escape(tmpl);
  }

  v8::Local<v8::Object> Crypto::wrap(v8::Local<v8::Context> context)
  {
    v8::Isolate* isolate = context->GetIsolate();
    v8::EscapableHandleScope handle_scope(isolate);

    v8::Local<v8::ObjectTemplate> tmpl =
      get_cached_object_template<Crypto>(isolate);

    v8::Local<v8::Object> result = tmpl->NewInstance(context).ToLocalChecked();

    return handle_scope.Escape(result);
  }

} // namespace ccf::v8_tmpl

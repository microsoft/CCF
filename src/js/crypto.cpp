// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "crypto/entropy.h"
#include "crypto/key_wrap.h"
#include "crypto/rsa_key_pair.h"
#include "tls/ca.h"

#include <quickjs/quickjs.h>

namespace js
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc99-extensions"

  static JSValue js_generate_aes_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    int32_t key_size;
    if (JS_ToInt32(ctx, &key_size, argv[0]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    // Supported key sizes for AES.
    if (key_size != 128 && key_size != 192 && key_size != 256)
    {
      JS_ThrowRangeError(ctx, "invalid key size");
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::vector<uint8_t> key = crypto::create_entropy()->random(key_size / 8);

    return JS_NewArrayBufferCopy(ctx, key.data(), key.size());
  }

  static JSValue js_generate_rsa_key_pair(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1 && argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1 or 2", argc);

    uint32_t key_size = 0, key_exponent = 0;
    if (JS_ToUint32(ctx, &key_size, argv[0]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    if (argc == 2 && JS_ToUint32(ctx, &key_exponent, argv[1]) < 0)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::shared_ptr<crypto::RSAKeyPair> k;
    if (argc == 1)
    {
      k = crypto::make_rsa_key_pair(key_size);
    }
    else
    {
      k = crypto::make_rsa_key_pair(key_size, key_exponent);
    }

    crypto::Pem prv = k->private_key_pem();
    crypto::Pem pub = k->public_key_pem();

    auto r = JS_NewObject(ctx);
    JS_SetPropertyStr(
      ctx, r, "privateKey", JS_NewString(ctx, (char*)prv.data()));
    JS_SetPropertyStr(
      ctx, r, "publicKey", JS_NewString(ctx, (char*)pub.data()));
    return r;
  }

  static JSValue js_digest(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto digest_algo_name_cstr = auto_free(JS_ToCString(ctx, argv[0]));
    if (!digest_algo_name_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    if (std::string(digest_algo_name_cstr) != "SHA-256")
    {
      JS_ThrowRangeError(
        ctx, "unsupported digest algorithm, supported: SHA-256");
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[1]);
    if (!data)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto h = crypto::SHA256(data, data_size);
    return JS_NewArrayBufferCopy(ctx, h.data(), h.size());
  }

  static JSValue js_is_valid_x509_cert_bundle(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto pem_cstr = auto_free(JS_ToCString(ctx, argv[0]));
    if (!pem_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      std::string pem(pem_cstr);
      tls::CA ca(pem);
    }
    catch (const std::logic_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Chain: {}", e.what());
      return JS_FALSE;
    }

    return JS_TRUE;
  }

  static JSValue js_is_valid_x509_cert(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto pem_cstr = auto_free(JS_ToCString(ctx, argv[0]));
    if (!pem_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      std::string pem_str(pem_cstr);
      crypto::Pem pem(pem_str);
      crypto::make_unique_verifier(pem);
    }
    catch (const std::logic_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Cert: {}", e.what());
      return JS_FALSE;
    }

    return JS_TRUE;
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

  static JSValue js_is_valid_x509_cert_chain(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    // first arg: chain (concatenated PEM certs, first cert = target)
    // second arg: trusted (concatenated PEM certs)
    if (argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 2", argc);

    auto chain_js = argv[0];
    auto trusted_js = argv[1];

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto chain_cstr = auto_free(JS_ToCString(ctx, chain_js));
    if (!chain_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    auto trusted_cstr = auto_free(JS_ToCString(ctx, trusted_js));
    if (!trusted_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      auto chain_vec = split_x509_cert_bundle(chain_cstr);
      auto trusted_vec = split_x509_cert_bundle(trusted_cstr);
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
    }
    catch (const std::logic_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Chain: {}", e.what());
      return JS_FALSE;
    }

    return JS_TRUE;
  }

  static JSValue js_pem_to_id(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto pem_cstr = auto_free(JS_ToCString(ctx, argv[0]));
    if (!pem_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto pem = crypto::Pem(pem_cstr);
    auto der = crypto::make_verifier(pem)->cert_der();
    auto id = crypto::Sha256Hash(der).hex_str();

    return JS_NewString(ctx, id.c_str());
  }

  static JSValue js_wrap_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 3)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 3", argc);

    // API loosely modeled after
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/wrapKey.

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);
    if (!key)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    size_t wrapping_key_size;
    uint8_t* wrapping_key = JS_GetArrayBuffer(ctx, &wrapping_key_size, argv[1]);
    if (!wrapping_key)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    void* auto_free_ptr = JS_GetContextOpaque(ctx);
    js::Context& auto_free = *(js::Context*)auto_free_ptr;

    auto parameters = argv[2];
    JSValue wrap_algo_name_val =
      auto_free(JS_GetPropertyStr(ctx, parameters, "name"));

    auto wrap_algo_name_cstr = auto_free(JS_ToCString(ctx, wrap_algo_name_val));

    if (!wrap_algo_name_cstr)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      auto algo_name = std::string(wrap_algo_name_cstr);
      if (algo_name == "RSA-OAEP")
      {
        // key can in principle be arbitrary data (see note on maximum size
        // in rsa_key_pair.h). wrapping_key is a public RSA key.

        auto label_val = auto_free(JS_GetPropertyStr(ctx, parameters, "label"));
        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        auto wrapped_key = crypto::ckm_rsa_pkcs_oaep_wrap(
          crypto::Pem(wrapping_key, wrapping_key_size),
          {key, key + key_size},
          {label_buf, label_buf + label_buf_size});

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else if (algo_name == "AES-KWP")
      {
        std::vector<uint8_t> wrapped_key = crypto::ckm_aes_key_wrap_pad(
          {wrapping_key, wrapping_key + wrapping_key_size},
          {key, key + key_size});

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else if (algo_name == "RSA-OAEP-AES-KWP")
      {
        auto aes_key_size_value =
          auto_free(JS_GetPropertyStr(ctx, parameters, "aesKeySize"));
        int32_t aes_key_size = 0;
        if (JS_ToInt32(ctx, &aes_key_size, aes_key_size_value) < 0)
        {
          js::js_dump_error(ctx);
          return JS_EXCEPTION;
        }

        auto label_val = auto_free(JS_GetPropertyStr(ctx, parameters, "label"));
        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        auto wrapped_key = crypto::ckm_rsa_aes_key_wrap(
          aes_key_size,
          crypto::Pem(wrapping_key, wrapping_key_size),
          {key, key + key_size},
          {label_buf, label_buf + label_buf_size});

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else
      {
        JS_ThrowRangeError(
          ctx,
          "unsupported key wrapping algorithm, supported: RSA-OAEP, AES-KWP, "
          "RSA-OAEP-AES-KWP");
        js::js_dump_error(ctx);
        return JS_EXCEPTION;
      }
    }
    catch (std::exception& ex)
    {
      JS_ThrowRangeError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    catch (...)
    {
      JS_ThrowRangeError(ctx, "caught unknown exception");
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
  }

#pragma clang diagnostic pop

}
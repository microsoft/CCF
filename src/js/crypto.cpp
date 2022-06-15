// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/sha256.h"
#include "crypto/ecdsa.h"
#include "js/wrap.h"
#include "tls/ca.h"

#include <quickjs/quickjs.h>

namespace ccf::js
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
      auto e = JS_ThrowRangeError(ctx, "invalid key size");
      js::js_dump_error(ctx);
      return e;
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

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto digest_algo_name_str = jsctx.to_str(argv[0]);
    if (!digest_algo_name_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    if (*digest_algo_name_str != "SHA-256")
    {
      auto e = JS_ThrowRangeError(
        ctx, "unsupported digest algorithm, supported: SHA-256");
      js::js_dump_error(ctx);
      return e;
    }

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[1]);
    if (!data)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto h = crypto::sha256(data, data_size);
    return JS_NewArrayBufferCopy(ctx, h.data(), h.size());
  }

  static JSValue js_is_valid_x509_cert_bundle(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto pem = jsctx.to_str(argv[0]);
    if (!pem)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      tls::CA ca(pem.value());
    }
    catch (const std::logic_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Bundle: {}", e.what());
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

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto chain_str = jsctx.to_str(chain_js);
    if (!chain_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    auto trusted_str = jsctx.to_str(trusted_js);
    if (!trusted_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      auto chain_vec = split_x509_cert_bundle(*chain_str);
      auto trusted_vec = split_x509_cert_bundle(*trusted_str);
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
    catch (const std::runtime_error& e)
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

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto pem_str = jsctx.to_str(argv[0]);
    if (!pem_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto pem = crypto::Pem(*pem_str);
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

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto parameters = argv[2];
    JSValue wrap_algo_name_val =
      jsctx(JS_GetPropertyStr(ctx, parameters, "name"));

    auto wrap_algo_name_str = jsctx.to_str(wrap_algo_name_val);
    if (!wrap_algo_name_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      auto algo_name = std::string(*wrap_algo_name_str);
      if (algo_name == "RSA-OAEP")
      {
        // key can in principle be arbitrary data (see note on maximum size
        // in rsa_key_pair.h). wrapping_key is a public RSA key.

        auto label_val = jsctx(JS_GetPropertyStr(ctx, parameters, "label"));
        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (label_buf_size > 0)
        {
          label_opt = {label_buf, label_buf + label_buf_size};
        }

        auto wrapped_key = crypto::ckm_rsa_pkcs_oaep_wrap(
          crypto::Pem(wrapping_key, wrapping_key_size),
          {key, key + key_size},
          label_opt);

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
          jsctx(JS_GetPropertyStr(ctx, parameters, "aesKeySize"));
        int32_t aes_key_size = 0;
        if (JS_ToInt32(ctx, &aes_key_size, aes_key_size_value) < 0)
        {
          js::js_dump_error(ctx);
          return JS_EXCEPTION;
        }

        auto label_val = jsctx(JS_GetPropertyStr(ctx, parameters, "label"));
        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (label_buf_size > 0)
        {
          label_opt = {label_buf, label_buf + label_buf_size};
        }

        auto wrapped_key = crypto::ckm_rsa_aes_key_wrap(
          aes_key_size,
          crypto::Pem(wrapping_key, wrapping_key_size),
          {key, key + key_size},
          label_opt);

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else
      {
        auto e = JS_ThrowRangeError(
          ctx,
          "unsupported key wrapping algorithm, supported: RSA-OAEP, AES-KWP, "
          "RSA-OAEP-AES-KWP");
        js::js_dump_error(ctx);
        return e;
      }
    }
    catch (std::exception& ex)
    {
      auto e = JS_ThrowRangeError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return e;
    }
    catch (...)
    {
      auto e = JS_ThrowRangeError(ctx, "caught unknown exception");
      js::js_dump_error(ctx);
      return e;
    }
  }

  static JSValue js_verify_signature(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 4)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 4", argc);
    }

    // API loosely modeled after
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/verify.

    size_t signature_size;
    uint8_t* signature = JS_GetArrayBuffer(ctx, &signature_size, argv[2]);
    if (!signature)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[3]);
    if (!data)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto algorithm = argv[0];
    JSValue algo_name_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "name"));
    JSValue algo_hash_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "hash"));

    auto algo_name_str = jsctx.to_str(algo_name_val);
    if (!algo_name_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }
    auto algo_hash_str = jsctx.to_str(algo_hash_val);
    if (!algo_hash_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    auto key_str = jsctx.to_str(argv[1]);
    if (!key_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    try
    {
      auto algo_name = *algo_name_str;
      auto algo_hash = *algo_hash_str;
      auto key = *key_str;

      crypto::MDType mdtype;
      if (algo_hash == "SHA-256")
      {
        mdtype = crypto::MDType::SHA256;
      }
      else
      {
        auto e = JS_ThrowRangeError(
          ctx, "Unsupported hash algorithm, supported: SHA-256");
        js::js_dump_error(ctx);
        return e;
      }

      if (algo_name != "RSASSA-PKCS1-v1_5" && algo_name != "ECDSA")
      {
        auto e = JS_ThrowRangeError(
          ctx,
          "Unsupported signing algorithm, supported: RSASSA-PKCS1-v1_5, "
          "ECDSA");
        js::js_dump_error(ctx);
        return e;
      }

      std::vector<uint8_t> sig(signature, signature + signature_size);

      if (algo_name == "ECDSA")
      {
        sig = crypto::ecdsa_sig_p1363_to_der(sig);
      }

      auto is_cert = nonstd::starts_with(key, "-----BEGIN CERTIFICATE");

      bool valid = false;

      if (is_cert)
      {
        auto verifier = crypto::make_unique_verifier(key);
        valid =
          verifier->verify(data, data_size, sig.data(), sig.size(), mdtype);
      }
      else
      {
        auto public_key = crypto::make_public_key(key);
        valid =
          public_key->verify(data, data_size, sig.data(), sig.size(), mdtype);
      }

      return JS_NewBool(ctx, valid);
    }
    catch (std::exception& ex)
    {
      auto e = JS_ThrowRangeError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return e;
    }
  }

#pragma clang diagnostic pop
}

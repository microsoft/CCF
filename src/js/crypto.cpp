// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/ecdsa.h"
#include "ccf/crypto/eddsa_key_pair.h"
#include "ccf/crypto/entropy.h"
#include "ccf/crypto/key_wrap.h"
#include "ccf/crypto/rsa_key_pair.h"
#include "ccf/crypto/sha256.h"
#include "js/wrap.h"
#include "tls/ca.h"

#include <quickjs/quickjs.h>

namespace ccf::js
{
  static JSValue js_generate_aes_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    int32_t key_size;
    if (JS_ToInt32(ctx, &key_size, argv[0]) < 0)
    {
      return ccf::js::constants::Exception;
    }
    // Supported key sizes for AES.
    if (key_size != 128 && key_size != 192 && key_size != 256)
    {
      return JS_ThrowRangeError(
        ctx, "invalid key size (not one of 128, 192, 256)");
    }

    try
    {
      std::vector<uint8_t> key = crypto::create_entropy()->random(key_size / 8);
      return JS_NewArrayBufferCopy(ctx, key.data(), key.size());
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to generate AES key: %s", exc.what());
    }
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
      return ccf::js::constants::Exception;
    }

    if (argc == 2 && JS_ToUint32(ctx, &key_exponent, argv[1]) < 0)
    {
      return ccf::js::constants::Exception;
    }

    std::shared_ptr<crypto::RSAKeyPair> k;
    try
    {
      if (argc == 1)
      {
        k = crypto::make_rsa_key_pair(key_size);
      }
      else
      {
        k = crypto::make_rsa_key_pair(key_size, key_exponent);
      }
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to generate RSA key pair: %s", exc.what());
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    try
    {
      crypto::Pem prv = k->private_key_pem();
      crypto::Pem pub = k->public_key_pem();

      auto r = jsctx.new_obj();
      JS_CHECK_EXC(r);
      auto private_key = jsctx.new_string_len((char*)prv.data(), prv.size());
      OPENSSL_cleanse(prv.data(), prv.size());
      JS_CHECK_EXC(private_key);
      JS_CHECK_SET(r.set("privateKey", std::move(private_key)));
      auto public_key = jsctx.new_string_len((char*)pub.data(), pub.size());
      JS_CHECK_EXC(public_key);
      JS_CHECK_SET(r.set("publicKey", std::move(public_key)));

      return r.take();
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to serialise RSA key pair: %s", exc.what());
    }
  }

  static JSValue js_generate_ecdsa_key_pair(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto curve = jsctx.to_str(argv[0]);
    if (!curve)
    {
      return ccf::js::constants::Exception;
    }

    crypto::CurveID cid;
    if (curve == "secp256r1")
    {
      cid = crypto::CurveID::SECP256R1;
    }
    else if (curve == "secp256k1")
    {
      cid = crypto::CurveID::SECP256K1;
    }
    else if (curve == "secp384r1")
    {
      cid = crypto::CurveID::SECP384R1;
    }
    else
    {
      return JS_ThrowRangeError(
        ctx,
        "Unsupported curve id, supported: secp256r1, secp256k1, secp384r1");
    }

    try
    {
      auto k = crypto::make_key_pair(cid);

      crypto::Pem prv = k->private_key_pem();
      crypto::Pem pub = k->public_key_pem();

      auto r = jsctx.new_obj();
      JS_CHECK_EXC(r);
      auto private_key = jsctx.new_string_len((char*)prv.data(), prv.size());
      OPENSSL_cleanse(prv.data(), prv.size());
      JS_CHECK_EXC(private_key);
      JS_CHECK_SET(r.set("privateKey", std::move(private_key)));
      auto public_key = jsctx.new_string_len((char*)pub.data(), pub.size());
      JS_CHECK_EXC(public_key);
      JS_CHECK_SET(r.set("publicKey", std::move(public_key)));

      return r.take();
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to generate ECDSA key pair: %s", exc.what());
    }
  }

  static JSValue js_generate_eddsa_key_pair(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto curve = jsctx.to_str(argv[0]);
    if (!curve)
    {
      return ccf::js::constants::Exception;
    }

    crypto::CurveID cid;
    if (curve == "curve25519")
    {
      cid = crypto::CurveID::CURVE25519;
    }
    else
    {
      return JS_ThrowRangeError(
        ctx, "Unsupported curve id, supported: curve25519");
    }

    try
    {
      auto k = crypto::make_eddsa_key_pair(cid);

      crypto::Pem prv = k->private_key_pem();
      crypto::Pem pub = k->public_key_pem();

      auto r = jsctx.new_obj();
      JS_CHECK_EXC(r);
      auto private_key = jsctx.new_string_len((char*)prv.data(), prv.size());
      OPENSSL_cleanse(prv.data(), prv.size());
      JS_CHECK_EXC(private_key);
      JS_CHECK_SET(r.set("privateKey", std::move(private_key)));
      auto public_key = jsctx.new_string_len((char*)pub.data(), pub.size());
      JS_CHECK_EXC(public_key);
      JS_CHECK_SET(r.set("publicKey", std::move(public_key)));

      return r.take();
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to generate EdDSA key pair: %s", exc.what());
    }
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
      return ccf::js::constants::Exception;
    }

    if (*digest_algo_name_str != "SHA-256")
    {
      return JS_ThrowRangeError(
        ctx, "unsupported digest algorithm, supported: SHA-256");
    }

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[1]);
    if (!data)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto h = crypto::sha256(data, data_size);
      return JS_NewArrayBufferCopy(ctx, h.data(), h.size());
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Failed to digest: %s", exc.what());
    }
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
      return ccf::js::constants::Exception;
    }

    try
    {
      tls::CA ca(pem.value());
    }
    catch (const std::runtime_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Bundle: {}", e.what());
      return ccf::js::constants::False;
    }
    catch (const std::logic_error& e)
    {
      return JS_ThrowInternalError(
        ctx, "isValidX509Bundle failed: %s", e.what());
    }

    return ccf::js::constants::True;
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
      return ccf::js::constants::Exception;
    }
    auto trusted_str = jsctx.to_str(trusted_js);
    if (!trusted_str)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto chain_vec = crypto::split_x509_cert_bundle(*chain_str);
      auto trusted_vec = crypto::split_x509_cert_bundle(*trusted_str);
      if (chain_vec.empty() || trusted_vec.empty())
      {
        throw std::runtime_error(
          "chain/trusted arguments must contain at least one certificate");
      }

      auto& target_pem = chain_vec[0];
      std::vector<const crypto::Pem*> chain_ptr;
      for (auto it = chain_vec.begin() + 1; it != chain_vec.end(); it++)
      {
        chain_ptr.push_back(&*it);
      }
      std::vector<const crypto::Pem*> trusted_ptr;
      for (auto& pem : trusted_vec)
      {
        trusted_ptr.push_back(&pem);
      }

      auto verifier = crypto::make_unique_verifier(target_pem);
      if (!verifier->verify_certificate(trusted_ptr, chain_ptr))
      {
        throw std::runtime_error("certificate chain is invalid");
      }
    }
    catch (const std::runtime_error& e)
    {
      LOG_DEBUG_FMT("isValidX509Chain: {}", e.what());
      return ccf::js::constants::False;
    }
    catch (const std::logic_error& e)
    {
      return JS_ThrowInternalError(
        ctx, "isValidX509Chain failed: %s", e.what());
    }

    return ccf::js::constants::True;
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
      return ccf::js::constants::Exception;
    }

    try
    {
      auto pem = crypto::Pem(*pem_str);
      auto der = crypto::make_verifier(pem)->cert_der();
      auto id = crypto::Sha256Hash(der).hex_str();

      return JS_NewString(ctx, id.c_str());
    }
    catch (const std::exception& exc)
    {
      return JS_ThrowInternalError(ctx, "Failed to parse PEM: %s", exc.what());
    }
  }

  template <typename T>
  static JSValue js_pem_to_jwk(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1 && argc != 2)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1 or 2", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto pem_str = jsctx.to_str(argv[0]);
    if (!pem_str)
    {
      return ccf::js::constants::Exception;
    }

    std::optional<std::string> kid = std::nullopt;
    if (argc == 2)
    {
      auto kid_str = jsctx.to_str(argv[1]);
      if (!kid_str)
      {
        return ccf::js::constants::Exception;
      }
      kid = kid_str;
    }

    T jwk;
    try
    {
      if constexpr (std::is_same_v<T, crypto::JsonWebKeyECPublic>)
      {
        auto pubk = crypto::make_public_key(*pem_str);
        jwk = pubk->public_key_jwk(kid);
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyECPrivate>)
      {
        auto kp = crypto::make_key_pair(*pem_str);
        jwk = kp->private_key_jwk(kid);
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyRSAPublic>)
      {
        auto pubk = crypto::make_rsa_public_key(*pem_str);
        jwk = pubk->public_key_jwk_rsa(kid);
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyRSAPrivate>)
      {
        auto kp = crypto::make_rsa_key_pair(*pem_str);
        jwk = kp->private_key_jwk_rsa(kid);
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyEdDSAPublic>)
      {
        auto pubk = crypto::make_eddsa_public_key(*pem_str);
        jwk = pubk->public_key_jwk_eddsa(kid);
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyEdDSAPrivate>)
      {
        auto kp = crypto::make_eddsa_key_pair(*pem_str);
        jwk = kp->private_key_jwk_eddsa(kid);
      }
      else
      {
        static_assert(nonstd::dependent_false_v<T>, "Unknown type");
      }
    }
    catch (const std::exception& ex)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to convert pem to jwk: %s", ex.what());
    }

    try
    {
      auto jwk_str = nlohmann::json(jwk).dump();
      return JS_ParseJSON(ctx, jwk_str.c_str(), jwk_str.size(), "<jwk>");
    }
    catch (const std::exception& ex)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to serialise jwk: %s", ex.what());
    }
  }

  template <typename T>
  static JSValue js_jwk_to_pem(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto jwk_str =
      jsctx.to_str(jsctx.json_stringify(JSWrappedValue(ctx, argv[0])));
    if (!jwk_str)
    {
      return ccf::js::constants::Exception;
    }

    crypto::Pem pem;

    try
    {
      T jwk = nlohmann::json::parse(jwk_str.value());

      if constexpr (std::is_same_v<T, crypto::JsonWebKeyECPublic>)
      {
        auto pubk = crypto::make_public_key(jwk);
        pem = pubk->public_key_pem();
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyECPrivate>)
      {
        auto kp = crypto::make_key_pair(jwk);
        pem = kp->private_key_pem();
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyRSAPublic>)
      {
        auto pubk = crypto::make_rsa_public_key(jwk);
        pem = pubk->public_key_pem();
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyRSAPrivate>)
      {
        auto kp = crypto::make_rsa_key_pair(jwk);
        pem = kp->private_key_pem();
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyEdDSAPublic>)
      {
        auto pubk = crypto::make_eddsa_public_key(jwk);
        pem = pubk->public_key_pem();
      }
      else if constexpr (std::is_same_v<T, crypto::JsonWebKeyEdDSAPrivate>)
      {
        auto kp = crypto::make_eddsa_key_pair(jwk);
        pem = kp->private_key_pem();
      }
      else
      {
        static_assert(nonstd::dependent_false_v<T>, "Unknown type");
      }
    }
    catch (const std::exception& ex)
    {
      auto e = JS_ThrowInternalError(
        ctx, "Failed to convert jwk to pem %s", ex.what());
    }

    auto pem_str = pem.str();
    return JS_NewString(ctx, pem.str().c_str());
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
      return ccf::js::constants::Exception;
    }

    size_t wrapping_key_size;
    uint8_t* wrapping_key = JS_GetArrayBuffer(ctx, &wrapping_key_size, argv[1]);
    if (!wrapping_key)
    {
      return ccf::js::constants::Exception;
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto parameters = argv[2];
    auto wrap_algo_name_val = jsctx(JS_GetPropertyStr(ctx, parameters, "name"));
    JS_CHECK_EXC(wrap_algo_name_val);

    auto wrap_algo_name_str = jsctx.to_str(wrap_algo_name_val);
    if (!wrap_algo_name_str)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto algo_name = *wrap_algo_name_str;
      if (algo_name == "RSA-OAEP")
      {
        // key can in principle be arbitrary data (see note on maximum size
        // in rsa_key_pair.h). wrapping_key is a public RSA key.

        auto label_val = jsctx(JS_GetPropertyStr(ctx, parameters, "label"));
        JS_CHECK_EXC(label_val);

        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (label_buf && label_buf_size > 0)
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
        std::vector<uint8_t> privateKey(
          wrapping_key, wrapping_key + wrapping_key_size);
        std::vector<uint8_t> wrapped_key =
          crypto::ckm_aes_key_wrap_pad(privateKey, {key, key + key_size});

        OPENSSL_cleanse(&privateKey, sizeof(privateKey));

        return JS_NewArrayBufferCopy(
          ctx, wrapped_key.data(), wrapped_key.size());
      }
      else if (algo_name == "RSA-OAEP-AES-KWP")
      {
        auto aes_key_size_value =
          jsctx(JS_GetPropertyStr(ctx, parameters, "aesKeySize"));
        JS_CHECK_EXC(aes_key_size_value);

        int32_t aes_key_size = 0;
        if (JS_ToInt32(ctx, &aes_key_size, aes_key_size_value) < 0)
        {
          return ccf::js::constants::Exception;
        }

        auto label_val = jsctx(JS_GetPropertyStr(ctx, parameters, "label"));
        JS_CHECK_EXC(label_val);

        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (label_buf && label_buf_size > 0)
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
        return JS_ThrowRangeError(
          ctx,
          "unsupported key wrapping algorithm, supported: RSA-OAEP, AES-KWP, "
          "RSA-OAEP-AES-KWP");
      }
    }
    catch (std::exception& ex)
    {
      return JS_ThrowInternalError(ctx, "Failed to wrap key: %s", ex.what());
    }
    catch (...)
    {
      return JS_ThrowRangeError(ctx, "caught unknown exception");
    }
  }

  static JSValue js_unwrap_key(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 3)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 3", argc);

    // API loosely modeled after
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/unwrapKey.

    size_t key_size;
    uint8_t* key = JS_GetArrayBuffer(ctx, &key_size, argv[0]);
    if (!key)
    {
      return ccf::js::constants::Exception;
    }

    size_t unwrapping_key_size;
    uint8_t* unwrapping_key =
      JS_GetArrayBuffer(ctx, &unwrapping_key_size, argv[1]);
    if (!unwrapping_key)
    {
      return ccf::js::constants::Exception;
    }

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    auto parameters = argv[2];
    auto wrap_algo_name_val = jsctx(JS_GetPropertyStr(ctx, parameters, "name"));
    JS_CHECK_EXC(wrap_algo_name_val);

    auto wrap_algo_name_str = jsctx.to_str(wrap_algo_name_val);
    if (!wrap_algo_name_str)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto algo_name = *wrap_algo_name_str;
      if (algo_name == "RSA-OAEP")
      {
        // key can in principle be arbitrary data (see note on maximum size
        // in rsa_key_pair.h). unwrapping_key is a private RSA key.

        auto label_val = jsctx(JS_GetPropertyStr(ctx, parameters, "label"));
        JS_CHECK_EXC(label_val);

        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (label_buf && label_buf_size > 0)
        {
          label_opt = {label_buf, label_buf + label_buf_size};
        }

        auto pemPrivateUnwrappingKey =
          crypto::Pem(unwrapping_key, unwrapping_key_size);
        auto unwrapped_key = crypto::ckm_rsa_pkcs_oaep_unwrap(
          pemPrivateUnwrappingKey, {key, key + key_size}, label_opt);

        OPENSSL_cleanse(
          pemPrivateUnwrappingKey.data(), pemPrivateUnwrappingKey.size());

        return JS_NewArrayBufferCopy(
          ctx, unwrapped_key.data(), unwrapped_key.size());
      }
      else if (algo_name == "AES-KWP")
      {
        std::vector<uint8_t> privateKey(
          unwrapping_key, unwrapping_key + unwrapping_key_size);
        std::vector<uint8_t> unwrapped_key =
          crypto::ckm_aes_key_unwrap_pad(privateKey, {key, key + key_size});

        OPENSSL_cleanse(&privateKey, sizeof(privateKey));

        return JS_NewArrayBufferCopy(
          ctx, unwrapped_key.data(), unwrapped_key.size());
      }
      else if (algo_name == "RSA-OAEP-AES-KWP")
      {
        auto aes_key_size_value =
          jsctx(JS_GetPropertyStr(ctx, parameters, "aesKeySize"));
        JS_CHECK_EXC(aes_key_size_value);

        int32_t aes_key_size = 0;
        if (JS_ToInt32(ctx, &aes_key_size, aes_key_size_value) < 0)
        {
          return ccf::js::constants::Exception;
        }

        auto label_val = jsctx(JS_GetPropertyStr(ctx, parameters, "label"));
        JS_CHECK_EXC(label_val);

        size_t label_buf_size = 0;
        uint8_t* label_buf = JS_GetArrayBuffer(ctx, &label_buf_size, label_val);

        std::optional<std::vector<uint8_t>> label_opt = std::nullopt;
        if (label_buf && label_buf_size > 0)
        {
          label_opt = {label_buf, label_buf + label_buf_size};
        }

        auto privPemUnwrappingKey =
          crypto::Pem(unwrapping_key, unwrapping_key_size);
        auto unwrapped_key = crypto::ckm_rsa_aes_key_unwrap(
          privPemUnwrappingKey, {key, key + key_size}, label_opt);

        OPENSSL_cleanse(
          privPemUnwrappingKey.data(), privPemUnwrappingKey.size());

        return JS_NewArrayBufferCopy(
          ctx, unwrapped_key.data(), unwrapped_key.size());
      }
      else
      {
        return JS_ThrowRangeError(
          ctx,
          "unsupported key unwrapping algorithm, supported: RSA-OAEP, AES-KWP, "
          "RSA-OAEP-AES-KWP");
      }
    }
    catch (std::exception& ex)
    {
      return JS_ThrowInternalError(ctx, "Failed to unwrap key: %s", ex.what());
    }
    catch (...)
    {
      return JS_ThrowRangeError(ctx, "caught unknown exception");
    }
  }

  static JSValue js_sign(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);

    if (argc != 3)
    {
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 3", argc);
    }

    auto algorithm = argv[0];

    auto algo_name_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "name"));
    JS_CHECK_EXC(algo_name_val);

    auto algo_hash_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "hash"));
    JS_CHECK_EXC(algo_hash_val);

    auto algo_name_str = jsctx.to_str(algo_name_val);
    if (!algo_name_str)
    {
      return ccf::js::constants::Exception;
    }

    auto key_str = jsctx.to_str(argv[1]);
    if (!key_str)
    {
      return ccf::js::constants::Exception;
    }
    auto key = *key_str;

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[2]);
    if (!data)
    {
      return ccf::js::constants::Exception;
    }
    std::vector<uint8_t> contents(data, data + data_size);

    // Handle algorithms that don't use algo_hash here
    if (*algo_name_str == "EdDSA")
    {
      try
      {
        crypto::Pem key_pem(key);
        auto key_pair = crypto::make_eddsa_key_pair(key_pem);
        auto sig = key_pair->sign(contents);
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      catch (const std::exception& ex)
      {
        return JS_ThrowInternalError(
          ctx, "Failed to sign with EdDSA pair: %s", ex.what());
      }
    }

    auto algo_hash_str = jsctx.to_str(algo_hash_val);
    if (!algo_hash_str)
    {
      return ccf::js::constants::Exception;
    }

    try
    {
      auto algo_name = *algo_name_str;
      auto algo_hash = *algo_hash_str;

      crypto::MDType mdtype;
      if (algo_hash == "SHA-256")
      {
        mdtype = crypto::MDType::SHA256;
      }
      else if (algo_hash == "SHA-384")
      {
        mdtype = crypto::MDType::SHA384;
      }
      else if (algo_hash == "SHA-512")
      {
        mdtype = crypto::MDType::SHA512;
      }
      else
      {
        return JS_ThrowRangeError(
          ctx,
          "Unsupported hash algorithm, supported: SHA-256, SHA-384, SHA-512");
      }

      if (algo_name == "ECDSA")
      {
        auto key_pair = crypto::make_key_pair(key);
        auto sig_der = key_pair->sign(contents, mdtype);
        auto sig =
          crypto::ecdsa_sig_der_to_p1363(sig_der, key_pair->get_curve_id());
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      else if (algo_name == "RSASSA-PKCS1-v1_5")
      {
        auto key_pair = crypto::make_rsa_key_pair(key);
        auto sig = key_pair->sign(contents, mdtype);
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      else if (algo_name == "HMAC")
      {
        std::vector<uint8_t> vkey(key.begin(), key.end());
        const auto sig = crypto::hmac(mdtype, vkey, contents);
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      else
      {
        return JS_ThrowRangeError(
          ctx,
          "Unsupported signing algorithm, supported: RSASSA-PKCS1-v1_5, "
          "ECDSA, EdDSA, HMAC");
      }
    }
    catch (const std::exception& ex)
    {
      return JS_ThrowInternalError(ctx, "Failed to sign: %s", ex.what());
    }
  }

  static bool verify_eddsa_signature(
    uint8_t* contents,
    size_t contents_size,
    uint8_t* signature,
    size_t signature_size,
    const std::string& pub_key)
  {
    auto public_key = crypto::make_eddsa_public_key(pub_key);
    return public_key->verify(
      contents, contents_size, signature, signature_size);
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
      return ccf::js::constants::Exception;
    }

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[3]);
    if (!data)
    {
      return ccf::js::constants::Exception;
    }

    auto algorithm = argv[0];

    auto algo_name_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "name"));
    JS_CHECK_EXC(algo_name_val);

    auto algo_hash_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "hash"));
    JS_CHECK_EXC(algo_hash_val);

    auto algo_name_str = jsctx.to_str(algo_name_val);
    if (!algo_name_str)
    {
      return ccf::js::constants::Exception;
    }

    auto key_str = jsctx.to_str(argv[1]);
    if (!key_str)
    {
      return ccf::js::constants::Exception;
    }

    // Handle algorithms that don't use algo_hash here
    if (*algo_name_str == "EdDSA")
    {
      try
      {
        return JS_NewBool(
          ctx,
          verify_eddsa_signature(
            data, data_size, signature, signature_size, *key_str));
      }
      catch (const std::exception& ex)
      {
        return JS_ThrowRangeError(
          ctx, "Failed to verify EdDSA signature: %s", ex.what());
      }
    }

    auto algo_hash_str = jsctx.to_str(algo_hash_val);
    if (!algo_hash_str)
    {
      return ccf::js::constants::Exception;
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
        return JS_ThrowRangeError(
          ctx, "Unsupported hash algorithm, supported: SHA-256");
      }

      if (algo_name != "RSASSA-PKCS1-v1_5" && algo_name != "ECDSA")
      {
        return JS_ThrowRangeError(
          ctx,
          "Unsupported signing algorithm, supported: RSASSA-PKCS1-v1_5, "
          "ECDSA, EdDSA");
      }

      std::vector<uint8_t> sig(signature, signature + signature_size);

      if (algo_name == "ECDSA")
      {
        sig = crypto::ecdsa_sig_p1363_to_der(sig);
      }

      auto is_cert = key.starts_with("-----BEGIN CERTIFICATE");

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
    catch (const std::exception& ex)
    {
      return JS_ThrowInternalError(
        ctx, "Failed to verify signature: %s", ex.what());
    }
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/eddsa_key_pair.h"
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

  static JSValue js_generate_ecdsa_key_pair(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto curve = jsctx.to_str(argv[0]);

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
    auto k = crypto::make_key_pair(cid);

    crypto::Pem prv = k->private_key_pem();
    crypto::Pem pub = k->public_key_pem();

    auto r = JS_NewObject(ctx);
    JS_SetPropertyStr(
      ctx, r, "privateKey", JS_NewString(ctx, (char*)prv.data()));
    JS_SetPropertyStr(
      ctx, r, "publicKey", JS_NewString(ctx, (char*)pub.data()));
    return r;
  }

  static JSValue js_generate_eddsa_key_pair(
    JSContext* ctx, JSValueConst, int argc, JSValueConst* argv)
  {
    if (argc != 1)
      return JS_ThrowTypeError(
        ctx, "Passed %d arguments, but expected 1", argc);

    js::Context& jsctx = *(js::Context*)JS_GetContextOpaque(ctx);
    auto curve = jsctx.to_str(argv[0]);

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
    auto k = crypto::make_eddsa_key_pair(cid);

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
      auto chain_vec = crypto::split_x509_cert_bundle(*chain_str);
      auto trusted_vec = crypto::split_x509_cert_bundle(*trusted_str);
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
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    std::optional<std::string> kid = std::nullopt;
    if (argc == 2)
    {
      auto kid_str = jsctx.to_str(argv[1]);
      if (!kid_str)
      {
        js::js_dump_error(ctx);
        return JS_EXCEPTION;
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
      auto e = JS_ThrowRangeError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return e;
    }

    auto jwk_str = nlohmann::json(jwk).dump();
    return JS_ParseJSON(ctx, jwk_str.c_str(), jwk_str.size(), "<jwk>");
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

    JSValue algo_name_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "name"));
    JSValue algo_hash_val = jsctx(JS_GetPropertyStr(ctx, algorithm, "hash"));

    auto algo_name_str = jsctx.to_str(algo_name_val);

    if (!algo_name_str)
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
    auto key = *key_str;

    size_t data_size;
    uint8_t* data = JS_GetArrayBuffer(ctx, &data_size, argv[2]);
    if (!data)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    // Handle algorithms that don't use algo_hash here
    if (*algo_name_str == "EdDSA")
    {
      try
      {
        std::vector<uint8_t> contents(data, data + data_size);
        crypto::Pem key_pem(key);
        auto key_pair = crypto::make_eddsa_key_pair(key_pem);
        auto sig = key_pair->sign(contents);
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      catch (const std::exception& ex)
      {
        auto e = JS_ThrowInternalError(ctx, "%s", ex.what());
        js::js_dump_error(ctx);
        return e;
      }
    }

    auto algo_hash_str = jsctx.to_str(algo_hash_val);
    if (!algo_hash_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
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
      else
      {
        auto e = JS_ThrowRangeError(
          ctx, "Unsupported hash algorithm, supported: SHA-256");
        js::js_dump_error(ctx);
        return e;
      }

      if (algo_name == "ECDSA")
      {
        std::vector<uint8_t> contents(data, data + data_size);
        auto key_pair = crypto::make_key_pair(key);
        auto sig_der = key_pair->sign(contents, mdtype);
        auto sig =
          crypto::ecdsa_sig_der_to_p1363(sig_der, key_pair->get_curve_id());
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      else if (algo_name == "RSASSA-PKCS1-v1_5")
      {
        std::vector<uint8_t> contents(data, data + data_size);
        auto key_pair = crypto::make_rsa_key_pair(key);
        auto sig = key_pair->sign(contents, mdtype);
        return JS_NewArrayBufferCopy(ctx, sig.data(), sig.size());
      }
      else
      {
        auto e = JS_ThrowRangeError(
          ctx,
          "Unsupported signing algorithm, supported: RSASSA-PKCS1-v1_5, "
          "ECDSA, EdDSA");
        js::js_dump_error(ctx);
        return e;
      }
    }
    catch (const std::exception& ex)
    {
      auto e = JS_ThrowInternalError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return e;
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

    auto key_str = jsctx.to_str(argv[1]);
    if (!key_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
    }

    if (!algo_name_str)
    {
      js::js_dump_error(ctx);
      return JS_EXCEPTION;
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
        auto e = JS_ThrowRangeError(ctx, "%s", ex.what());
        js::js_dump_error(ctx);
        return e;
      }
    }

    auto algo_hash_str = jsctx.to_str(algo_hash_val);
    if (!algo_hash_str)
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
          "ECDSA, EdDSA");
        js::js_dump_error(ctx);
        return e;
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
      auto e = JS_ThrowRangeError(ctx, "%s", ex.what());
      js::js_dump_error(ctx);
      return e;
    }
  }

#pragma clang diagnostic pop
}

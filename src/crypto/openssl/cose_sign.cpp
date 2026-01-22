// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_sign.h"

#include "crypto/cbor.h"
#include "ds/internal_logger.h"

#include <openssl/evp.h>
#include <t_cose/src/t_cose_crypto.h>
#include <t_cose/src/t_cose_util.h>

namespace
{
  std::optional<int> key_to_cose_alg_id(
    const ccf::crypto::ECPublicKey_OpenSSL& key)
  {
    const auto cid = key.get_curve_id();
    switch (cid)
    {
      case ccf::crypto::CurveID::SECP256R1:
        return T_COSE_ALGORITHM_ES256;
      case ccf::crypto::CurveID::SECP384R1:
        return T_COSE_ALGORITHM_ES384;
      default:
        return std::nullopt;
    }
  }

  t_cose_key init_signing_key_and_set_phdr(
    const ccf::crypto::ECKeyPair_OpenSSL& key,
    int32_t algorithm_id,
    ccf::cbor::Value& protected_headers)
  {
    using namespace ccf::cbor;

    bool alg_set{true};
    try
    {
      std::ignore = protected_headers->map_at(
        ccf::cbor::make_signed(ccf::crypto::COSE_PHEADER_KEY_ALG));
    }
    catch (const CBORDecodeError& err)
    {
      if (err.error_code() == Error::KEY_NOT_FOUND)
      {
        alg_set = false;
      }
      else
      {
        throw ccf::crypto::COSESignError(
          fmt::format("Failed to parse protected header: {}", err.what()));
      }
    }

    if (alg_set)
    {
      throw ccf::crypto::COSESignError(
        "Protected headers should not have alg(1) set");
    }

    auto& items = std::get<Map>(protected_headers->value).items;
    items.insert(
      items.begin(),
      {make_signed(ccf::crypto::COSE_PHEADER_KEY_ALG),
       make_signed(algorithm_id)});

    EVP_PKEY* evp_key = key;
    t_cose_key signing_key = {};
    signing_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    signing_key.k.key_ptr = evp_key;

    return signing_key;
  }

  q_useful_buf_c cose_sign(
    t_cose_key signing_key,
    int32_t algorithm_id,
    std::span<const uint8_t> phdr,
    std::span<const uint8_t> payload,
    std::span<uint8_t> signature)
  {
    q_useful_buf_c phdr_buf{phdr.data(), phdr.size()};
    q_useful_buf_c payload_buf{payload.data(), payload.size()};
    std::vector<uint8_t> tbs(T_COSE_CRYPTO_MAX_HASH_SIZE);
    UsefulBuf buffer_for_tbs_hash{tbs.data(), tbs.size()};
    q_useful_buf_c tbs_hash{};

    auto err = create_tbs_hash(
      algorithm_id,
      phdr_buf,
      NULL_Q_USEFUL_BUF_C,
      payload_buf,
      buffer_for_tbs_hash,
      &tbs_hash);

    if (err != 0)
    {
      throw ccf::crypto::COSESignError(
        fmt::format("Failed to create TBS with err: {}", err));
    }

    UsefulBuf signature_buf{signature.data(), signature.size()};
    q_useful_buf_c out_signature{};
    err = t_cose_crypto_sign(
      algorithm_id, signing_key, tbs_hash, signature_buf, &out_signature);

    if (err != 0)
    {
      throw ccf::crypto::COSESignError(
        fmt::format("Failed to cose_sign1 with err: {}", err));
    }

    return out_signature;
  }
}

namespace ccf::crypto
{
  std::vector<uint8_t> cose_sign1(
    const ECKeyPair_OpenSSL& key,
    ccf::cbor::Value protected_headers,
    std::span<const uint8_t> payload,
    bool detached_payload)
  {
    if (protected_headers == nullptr)
    {
      throw ccf::crypto::COSESignError("Unsupported missing protected headers");
    }

    const auto algorithm_id = key_to_cose_alg_id(key);
    if (!algorithm_id.has_value())
    {
      throw ccf::crypto::COSESignError("Unsupported key type");
    }

    auto signing_key = init_signing_key_and_set_phdr(
      key, algorithm_id.value(), protected_headers);

    size_t sig_len{0};
    auto err =
      t_cose_crypto_sig_size(algorithm_id.value(), signing_key, &sig_len);

    if (err != 0 || sig_len == 0)
    {
      throw ccf::crypto::COSESignError(
        fmt::format("Failed to calculate signature size with err: {}", err));
    }

    std::vector<uint8_t> signature(sig_len);
    auto phdr_cbor = ccf::cbor::serialize(protected_headers);
    auto signature_buf = cose_sign(
      signing_key, algorithm_id.value(), phdr_cbor, payload, signature);

    if (signature_buf.ptr != signature.data())
    {
      throw ccf::crypto::COSESignError(fmt::format(
        "Failed to match signature address {} to pre-allocated buffer {}",
        signature_buf.ptr,
        (void*)signature.data()));
    }

    if (signature_buf.len > signature.size())
    {
      throw ccf::crypto::COSESignError(fmt::format(
        "Signature size {} exceeds pre-allocated buffer size {}",
        signature_buf.len,
        signature.size()));
    }

    signature.resize(signature_buf.len);
    signature.shrink_to_fit();

    using namespace ccf::cbor;

    std::vector<Value> cose_array;
    cose_array.push_back(make_bytes(phdr_cbor));
    cose_array.push_back(make_map({}));
    if (detached_payload)
    {
      cose_array.push_back(make_simple(SimpleValue::Null));
    }
    else
    {
      cose_array.push_back(make_bytes(payload));
    }
    cose_array.push_back(make_bytes(signature));

    auto envelope = make_tagged(18, make_array(std::move(cose_array)));
    try
    {
      return serialize(envelope);
    }
    catch (const CBOREncodeError& err)
    {
      throw ccf::crypto::COSESignError(err.what());
    }
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_sign.h"

#include "ccf/ds/logger.h"

#include <openssl/evp.h>

namespace
{
  static constexpr size_t extra_size_for_int_tag = 1; // type
  static constexpr size_t extra_size_for_seq_tag = 1 + 8; // type + size

  size_t estimate_buffer_size(
    const std::vector<ccf::crypto::COSEParametersFactory>& protected_headers,
    std::span<const uint8_t> payload)
  {
    size_t result =
      300; // bytes for metadata even everything else is empty. This's the most
           // often used value in the t_cose examples, however no recommendation
           // is provided which one to use. We will consider this an affordable
           // starting point, as soon as we don't expect a shortage of memory on
           // the target platforms.

    result = std::accumulate(
      protected_headers.begin(),
      protected_headers.end(),
      result,
      [](auto result, const auto& factory) {
        return result + factory.estimated_size();
      });

    return result + payload.size();
  }

  void encode_protected_headers(
    t_cose_sign1_sign_ctx* ctx,
    QCBOREncodeContext* encode_ctx,
    const std::vector<ccf::crypto::COSEParametersFactory>& protected_headers)
  {
    QCBOREncode_BstrWrap(encode_ctx);
    QCBOREncode_OpenMap(encode_ctx);

    // This's what the t_cose implementation of `encode_protected_parameters`
    // sets unconditionally.
    QCBOREncode_AddInt64ToMapN(
      encode_ctx, ccf::crypto::COSE_PHEADER_KEY_ALG, ctx->cose_algorithm_id);

    // Caller-provided headers follow
    for (const auto& factory : protected_headers)
    {
      factory.apply(encode_ctx);
    }

    QCBOREncode_CloseMap(encode_ctx);
    QCBOREncode_CloseBstrWrap2(encode_ctx, false, &ctx->protected_parameters);
  }

  /* The original `t_cose_sign1_encode_parameters` can't accept a custom set of
   parameters to be encoded into headers. This version tags the context as
   COSE_SIGN1 and encodes the protected headers in the following order:
     - defaults
       - algorithm version
     - those provided by caller
   */
  void encode_parameters_custom(
    struct t_cose_sign1_sign_ctx* me,
    QCBOREncodeContext* cbor_encode,
    const std::vector<ccf::crypto::COSEParametersFactory>& protected_headers)
  {
    encode_protected_headers(me, cbor_encode, protected_headers);

    QCBOREncode_OpenMap(cbor_encode);
    // Explicitly leave unprotected headers empty to be an empty map.
    QCBOREncode_CloseMap(cbor_encode);
  }
}

namespace ccf::crypto
{
  std::optional<int> key_to_cose_alg_id(
    const ccf::crypto::PublicKey_OpenSSL& key)
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

  COSEParametersFactory cose_params_int_int(int64_t key, int64_t value)
  {
    const size_t args_size = sizeof(key) + sizeof(value) +
      extra_size_for_int_tag + extra_size_for_int_tag;
    return COSEParametersFactory(
      [=](QCBOREncodeContext* ctx) {
        QCBOREncode_AddInt64ToMapN(ctx, key, value);
      },
      args_size);
  }

  COSEParametersFactory cose_params_int_string(
    int64_t key, const std::string& value)
  {
    const size_t args_size = sizeof(key) + value.size() +
      extra_size_for_int_tag + extra_size_for_seq_tag;
    return COSEParametersFactory(
      [=](QCBOREncodeContext* ctx) {
        QCBOREncode_AddSZStringToMapN(ctx, key, value.data());
      },
      args_size);
  }

  COSEParametersFactory cose_params_string_int(
    const std::string& key, int64_t value)
  {
    const size_t args_size = key.size() + sizeof(value) +
      extra_size_for_seq_tag + extra_size_for_int_tag;
    return COSEParametersFactory(
      [=](QCBOREncodeContext* ctx) {
        QCBOREncode_AddSZString(ctx, key.data());
        QCBOREncode_AddInt64(ctx, value);
      },
      args_size);
  }

  COSEParametersFactory cose_params_string_string(
    const std::string& key, const std::string& value)
  {
    const size_t args_size = key.size() + value.size() +
      extra_size_for_seq_tag + extra_size_for_seq_tag;
    return COSEParametersFactory(
      [=](QCBOREncodeContext* ctx) {
        QCBOREncode_AddSZString(ctx, key.data());
        QCBOREncode_AddSZString(ctx, value.data());
      },
      args_size);
  }

  COSEParametersFactory cose_params_int_bytes(
    int64_t key, const std::vector<uint8_t>& value)
  {
    const size_t args_size = sizeof(key) + value.size() +
      +extra_size_for_int_tag + extra_size_for_seq_tag;
    q_useful_buf_c buf{value.data(), value.size()};
    return COSEParametersFactory(
      [=](QCBOREncodeContext* ctx) {
        QCBOREncode_AddBytesToMapN(ctx, key, buf);
      },
      args_size);
  }

  COSEParametersFactory cose_params_string_bytes(
    const std::string& key, const std::vector<uint8_t>& value)
  {
    const size_t args_size = key.size() + value.size() +
      extra_size_for_seq_tag + extra_size_for_seq_tag;
    q_useful_buf_c buf{value.data(), value.size()};
    return COSEParametersFactory(
      [=](QCBOREncodeContext* ctx) {
        QCBOREncode_AddSZString(ctx, key.data());
        QCBOREncode_AddBytes(ctx, buf);
      },
      args_size);
  }

  std::vector<uint8_t> cose_sign1(
    const KeyPair_OpenSSL& key,
    const std::vector<COSEParametersFactory>& protected_headers,
    std::span<const uint8_t> payload,
    bool detached_payload)
  {
    const auto buf_size = estimate_buffer_size(protected_headers, payload);
    std::vector<uint8_t> underlying_buffer(buf_size);
    q_useful_buf signed_cose_buffer{underlying_buffer.data(), buf_size};

    QCBOREncodeContext cbor_encode;
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_ctx sign_ctx;
    const auto algorithm_id = key_to_cose_alg_id(key);
    if (!algorithm_id.has_value())
    {
      throw ccf::crypto::COSESignError(fmt::format("Unsupported key type"));
    }

    t_cose_sign1_sign_init(&sign_ctx, 0, *algorithm_id);

    EVP_PKEY* evp_key = key;
    t_cose_key signing_key;
    signing_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    signing_key.k.key_ptr = evp_key;

    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    QCBOREncode_AddTag(&cbor_encode, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(&cbor_encode);

    encode_parameters_custom(&sign_ctx, &cbor_encode, protected_headers);

    if (detached_payload)
    {
      // Mark empty payload explicitly.
      QCBOREncode_AddNULL(&cbor_encode);
    }
    else
    {
      UsefulBufC payload_buffer{underlying_buffer.data(), buf_size};
      QCBOREncode_AddBytes(&cbor_encode, payload_buffer);
    }

    // If payload is empty - we still want to sign. Putting NULL_Q_USEFUL_BUF_C,
    // however, makes t_cose think that the payload is included into the
    // context. Luckily, passing empty string instead works, so t_cose works
    // emplaces it for TBS (to be signed) as an empty byte sequence.
    q_useful_buf_c payload_to_encode = {"", 0};
    if (!payload.empty())
    {
      payload_to_encode.ptr = payload.data();
      payload_to_encode.len = payload.size();
    }
    auto err = t_cose_sign1_encode_signature_aad_internal(
      &sign_ctx, NULL_Q_USEFUL_BUF_C, payload_to_encode, &cbor_encode);
    if (err)
    {
      throw COSESignError(
        fmt::format("Can't encode signature with error code {}", err));
    }

    struct q_useful_buf_c signed_cose;
    auto qerr = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if (qerr)
    {
      throw COSESignError(
        fmt::format("Can't finish QCBOR encoding with error code {}", err));
    }

    // Memory address is said to match:
    // github.com/laurencelundblade/QCBOR/blob/v1.4.1/inc/qcbor/qcbor_encode.h#L2190-L2191
    assert(signed_cose.ptr == underlying_buffer.data());

    underlying_buffer.resize(signed_cose.len);
    underlying_buffer.shrink_to_fit();
    return underlying_buffer;
  }
}

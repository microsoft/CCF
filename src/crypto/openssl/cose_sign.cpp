// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/openssl/cose_sign.h"

#include "ccf/ds/logger.h"

#include <openssl/evp.h>
#include <t_cose/t_cose_sign1_sign.h>

namespace
{
  constexpr int64_t COSE_HEADER_PARAM_ALG =
    1; // Duplicate of t_cose::COSE_HEADER_PARAM_ALG to keep it compatible.

  size_t estimate_buffer_size(
    const ccf::crypto::COSEProtectedHeaders& protected_headers,
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
      [](auto result, const auto& kv) {
        return result + sizeof(kv.first) + kv.second.size();
      });

    return result + payload.size();
  }

  void encode_protected_headers(
    t_cose_sign1_sign_ctx* ctx,
    QCBOREncodeContext* encode_ctx,
    const ccf::crypto::COSEProtectedHeaders& protected_headers)
  {
    QCBOREncode_BstrWrap(encode_ctx);
    QCBOREncode_OpenMap(encode_ctx);

    // This's what the t_cose implementation of `encode_protected_parameters`
    // sets unconditionally.
    QCBOREncode_AddInt64ToMapN(
      encode_ctx, COSE_HEADER_PARAM_ALG, ctx->cose_algorithm_id);

    // Caller-provided headers follow
    for (const auto& [label, value] : protected_headers)
    {
      QCBOREncode_AddSZStringToMapN(encode_ctx, label, value.c_str());
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
    const ccf::crypto::COSEProtectedHeaders& protected_headers)
  {
    QCBOREncode_AddTag(cbor_encode, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(cbor_encode);

    encode_protected_headers(me, cbor_encode, protected_headers);

    QCBOREncode_OpenMap(cbor_encode);
    // Explicitly leave unprotected headers empty to be an empty map.
    QCBOREncode_CloseMap(cbor_encode);
  }
}

namespace ccf::crypto
{
  std::vector<uint8_t> cose_sign1(
    EVP_PKEY* key,
    const COSEProtectedHeaders& protected_headers,
    std::span<const uint8_t> payload)
  {
    const auto buf_size = estimate_buffer_size(protected_headers, payload);
    Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, buf_size);

    QCBOREncodeContext cbor_encode;
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_ctx sign_ctx;
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);

    t_cose_key signing_key;
    signing_key.crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    signing_key.k.key_ptr = key;

    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, NULL_Q_USEFUL_BUF_C);

    encode_parameters_custom(&sign_ctx, &cbor_encode, protected_headers);

    // Mark empty payload manually.
    QCBOREncode_AddNULL(&cbor_encode);

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

    return {
      static_cast<const uint8_t*>(signed_cose.ptr),
      static_cast<const uint8_t*>(signed_cose.ptr) + signed_cose.len};
  }
}

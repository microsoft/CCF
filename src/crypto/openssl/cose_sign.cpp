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
    const std::unordered_map<int64_t, std::string>& protected_headers,
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
    const std::unordered_map<int64_t, std::string>& protected_headers)
  {
    QCBOREncode_BstrWrap(encode_ctx);
    QCBOREncode_OpenMap(encode_ctx);

    // This's what the original implementation of `encode_protected_parameters`
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
    const std::unordered_map<int64_t, std::string>& protected_headers)
  {
    QCBOREncode_AddTag(cbor_encode, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(cbor_encode);

    encode_protected_headers(me, cbor_encode, protected_headers);

    QCBOREncode_OpenMap(cbor_encode);
    // Explicitly leave unprotected headers empty to be an empty map.
    QCBOREncode_CloseMap(cbor_encode);
  }

  void encode_payload(
    QCBOREncodeContext* cbor_encode, std::span<const uint8_t> payload)
  {
    q_useful_buf_c payload_to_encode{payload.data(), payload.size()};

    QCBOREncode_BstrWrap(cbor_encode);
    QCBOREncode_OpenMap(cbor_encode);

    QCBOREncode_AddBytesToMap(cbor_encode, "data", payload_to_encode);

    QCBOREncode_CloseMap(cbor_encode);
    // Don't close BstrWrap because the signature encoding expects it to be
    // open.
  }
}

namespace ccf::crypto
{
  std::vector<uint8_t> cose_sign1(
    EVP_PKEY* key,
    const std::unordered_map<int64_t, std::string>& protected_headers,
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

    encode_payload(&cbor_encode, payload);

    auto err = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
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

    std::vector<uint8_t> cose_sign(signed_cose.len);
    std::memcpy((void*)cose_sign.data(), signed_cose.ptr, signed_cose.len);

    return cose_sign;
  }
}

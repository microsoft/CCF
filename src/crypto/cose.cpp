// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose.h"

#include <optional>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>

namespace ccf::cose::edit
{
  std::vector<uint8_t> insert_in_uhdr(
    const std::span<const uint8_t>& buf_,
    ssize_t key,
    op::Type op,
    const std::vector<uint8_t> value)
  {
    UsefulBufC buf{buf_.data(), buf_.size()};

    QCBORError rc;
    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&ctx, nullptr);
    rc = QCBORDecode_GetError(&ctx);
    if (rc != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 outer array");
    }

    auto tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 tag");
    }

    QCBORItem item;
    auto err = QCBORDecode_GetNext(&ctx, &item);
    if (err != QCBOR_SUCCESS || item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::logic_error(
        "Failed to parse COSE_Sign1 protected header as bstr");
    }
    std::span<const uint8_t> phdr = {
      (uint8_t*)item.val.string.ptr, item.val.string.len};

    // Skip unprotected header for now
    QCBORDecode_VGetNextConsume(&ctx, &item);

    std::optional<std::span<const uint8_t>> payload = std::nullopt;
    err = QCBORDecode_GetNext(&ctx, &item);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 payload");
    }
    if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
    {
      payload = {(uint8_t*)item.val.string.ptr, item.val.string.len};
    }
    else if (item.uDataType == QCBOR_TYPE_NULL)
    {
      // No payload
    }
    else
    {
      throw std::logic_error("Invalid COSE_Sign1 payload");
    }
    // QCBORDecode_PartialFinish() before and after should allow constructing a
    // span of the encoded payload, which can perhaps then be passed to
    // QCBOREncode_AddEncoded and would allow blindly copying the payload
    // without parsing it.

    err = QCBORDecode_GetNext(&ctx, &item);
    if (err != QCBOR_SUCCESS && item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 signature");
    }
    std::span<const uint8_t> signature = {
      (uint8_t*)item.val.string.ptr, item.val.string.len};

    QCBORDecode_ExitArray(&ctx);
    err = QCBORDecode_Finish(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1");
    }

    std::vector<uint8_t> output(buf_.size() + value.size() + 1024 /* too much, should be encoded key size + potential varint bump in sizes */);
    UsefulBuf output_buf{output.data(), output.size()};

    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_AddTag(&ectx, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(&ectx);
    QCBOREncode_AddBytes(&ectx, {phdr.data(), phdr.size()});
    QCBOREncode_OpenMap(&ectx);

    if (std::holds_alternative<op::Append>(op))
    {
      QCBOREncode_OpenArrayInMapN(&ectx, key);
      QCBOREncode_AddBytes(&ectx, {value.data(), value.size()});
      QCBOREncode_CloseArray(&ectx);
    }
    else if (std::holds_alternative<op::SetAtKey>(op))
    {
      QCBOREncode_OpenMapInMapN(&ectx, key);
      auto subkey = std::get<op::SetAtKey>(op).key;
      QCBOREncode_OpenArrayInMapN(&ectx, subkey);
      QCBOREncode_AddBytes(&ectx, {value.data(), value.size()});
      QCBOREncode_CloseArray(&ectx);
      QCBOREncode_CloseMap(&ectx);
    }
    else
    {
      throw std::logic_error("Invalid COSE_Sign1 edit operation");
    }

    QCBOREncode_CloseMap(&ectx);
    if (payload.has_value())
    {
      QCBOREncode_AddBytes(&ectx, {payload->data(), payload->size()});
    }
    else
    {
      QCBOREncode_AddSimple(&ectx, CBOR_SIMPLEV_NULL);
    }
    QCBOREncode_AddBytes(&ectx, {signature.data(), signature.size()});
    QCBOREncode_CloseArray(&ectx);

    UsefulBufC cose;
    err = QCBOREncode_Finish(&ectx, &cose);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to encode COSE_Sign1");
    }
    output.resize(cose.len);
    output.shrink_to_fit();
    return output;
  };
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/cose.h"

#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdexcept>
#include <vector>

namespace ccf::cose::edit
{
  std::vector<uint8_t> set_unprotected_header(
    const std::span<const uint8_t>& cose_input, const desc::Type& descriptor)
  {
    UsefulBufC buf{cose_input.data(), cose_input.size()};

    QCBORError err = QCBOR_SUCCESS;
    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);

    size_t pos_start = 0;
    size_t pos_end = 0;

    QCBORDecode_EnterArray(&ctx, nullptr);
    err = QCBORDecode_GetError(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 outer array");
    }

    auto tag = QCBORDecode_GetNthTagOfLast(&ctx, 0);
    if (tag != CBOR_TAG_COSE_SIGN1)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 tag");
    }

    QCBORItem item;
    err = QCBORDecode_GetNext(&ctx, &item);
    if (err != QCBOR_SUCCESS || item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::logic_error(
        "Failed to parse COSE_Sign1 protected header as bstr");
    }
    UsefulBufC phdr = {item.val.string.ptr, item.val.string.len};

    // Skip unprotected header
    QCBORDecode_VGetNextConsume(&ctx, &item);

    err = QCBORDecode_PartialFinish(&ctx, &pos_start);
    if (err != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED)
    {
      throw std::logic_error("Failed to find start of payload");
    }
    QCBORDecode_VGetNextConsume(&ctx, &item);
    err = QCBORDecode_PartialFinish(&ctx, &pos_end);
    if (err != QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED)
    {
      throw std::logic_error("Failed to find end of payload");
    }
    UsefulBufC payload = {cose_input.data() + pos_start, pos_end - pos_start};

    // QCBORDecode_PartialFinish() before and after should allow constructing a
    // span of the encoded payload, which can perhaps then be passed to
    // QCBOREncode_AddEncoded and would allow blindly copying the payload
    // without parsing it.

    err = QCBORDecode_GetNext(&ctx, &item);
    if (err != QCBOR_SUCCESS && item.uDataType != QCBOR_TYPE_BYTE_STRING)
    {
      throw std::logic_error("Failed to parse COSE_Sign1 signature");
    }
    UsefulBufC signature = {item.val.string.ptr, item.val.string.len};

    QCBORDecode_ExitArray(&ctx);
    err = QCBORDecode_Finish(&ctx);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to parse COSE_Sign1");
    }

    size_t additional_map_size = 0;

    if (std::holds_alternative<desc::Empty>(descriptor))
    {
      // Nothing to do
    }
    else if (std::holds_alternative<desc::Value>(descriptor))
    {
      const auto& [pos, key, value] = std::get<desc::Value>(descriptor);

      // Maximum expected size of the additional map, sub-map is the
      // worst-case scenario
      additional_map_size = QCBOR_HEAD_BUFFER_SIZE + // map
        QCBOR_HEAD_BUFFER_SIZE + // key
        sizeof(key) + // key
        QCBOR_HEAD_BUFFER_SIZE + // submap
        QCBOR_HEAD_BUFFER_SIZE + // subkey
        sizeof(pos::AtKey::key) + // subkey
        QCBOR_HEAD_BUFFER_SIZE + // value
        value.size(); // value
    }
    else
    {
      throw std::logic_error("Invalid COSE_Sign1 edit descriptor");
    }

    // We add one extra QCBOR_HEAD_BUFFER_SIZE, because we parse and re-encode
    // the protected header bstr, which involves variable integer encoding, just
    // in case the library does not pick the most compact encoding.
    std::vector<uint8_t> output(
      cose_input.size() + additional_map_size + QCBOR_HEAD_BUFFER_SIZE);
    UsefulBuf output_buf{output.data(), output.size()};

    QCBOREncodeContext ectx;
    QCBOREncode_Init(&ectx, output_buf);
    QCBOREncode_AddTag(&ectx, CBOR_TAG_COSE_SIGN1);
    QCBOREncode_OpenArray(&ectx);
    QCBOREncode_AddBytes(&ectx, phdr);
    QCBOREncode_OpenMap(&ectx);

    if (std::holds_alternative<desc::Empty>(descriptor))
    {
      // Nothing to do
    }
    else if (std::holds_alternative<desc::Value>(descriptor))
    {
      const auto& [pos, key, value] = std::get<desc::Value>(descriptor);

      if (std::holds_alternative<pos::InArray>(pos))
      {
        QCBOREncode_OpenArrayInMapN(&ectx, key);
        QCBOREncode_AddBytes(&ectx, {value.data(), value.size()});
        QCBOREncode_CloseArray(&ectx);
      }
      else if (std::holds_alternative<pos::AtKey>(pos))
      {
        QCBOREncode_OpenMapInMapN(&ectx, key);
        auto subkey = std::get<pos::AtKey>(pos).key;
        QCBOREncode_OpenArrayInMapN(&ectx, subkey);
        QCBOREncode_AddBytes(&ectx, {value.data(), value.size()});
        QCBOREncode_CloseArray(&ectx);
        QCBOREncode_CloseMap(&ectx);
      }
      else
      {
        throw std::logic_error("Invalid COSE_Sign1 edit operation");
      }
    }
    else
    {
      throw std::logic_error("Invalid COSE_Sign1 edit descriptor");
    }

    QCBOREncode_CloseMap(&ectx);
    QCBOREncode_AddEncoded(&ectx, payload);
    QCBOREncode_AddBytes(&ectx, signature);
    QCBOREncode_CloseArray(&ectx);

    UsefulBufC cose_output;
    err = QCBOREncode_Finish(&ectx, &cose_output);
    if (err != QCBOR_SUCCESS)
    {
      throw std::logic_error("Failed to encode COSE_Sign1");
    }
    output.resize(cose_output.len);
    output.shrink_to_fit();
    return output;
  };
}
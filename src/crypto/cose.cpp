// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include <stdexcept>

#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>

#include "ccf/crypto/cose.h"

namespace ccf::cose::edit
{
    // TODO: split COSE
    // TODO: append to map, if key is not found
    // TODO: extend array value in map, when key is found, or inject array otherwise
    void insert_receipt_in_uhdr(const std::span<const uint8_t>& buf_) {
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
    };
}
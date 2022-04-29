// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "node/tx_receipt_impl.h"

#include <v8.h>

namespace ccf::v8_tmpl
{
  class Receipt
  {
  public:
    static constexpr const char* NAME = "CCFReceipt";
    static v8::Local<v8::ObjectTemplate> create_template(v8::Isolate* isolate);

    static v8::Local<v8::Object> wrap(
      v8::Local<v8::Context> context, const ccf::TxReceiptImpl& receipt);
  };

} // namespace ccf::v8_tmpl

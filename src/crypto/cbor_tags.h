// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstdint>

namespace ccf::cbor::tag
{
  // https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.2
  static constexpr int64_t EPOCH_DATE_TIME = 1;

  // https://www.rfc-editor.org/rfc/rfc8152.html#section-2
  static constexpr int64_t COSE_SIGN_1 = 18;
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/sha256_hash.h"

#include <vector>

namespace ccf
{
  struct TxReceiptPathStep
  {
    enum
    {
      Left,
      Right
    } direction;

    crypto::Sha256Hash hash;
  };

  using TxReceiptPath = std::vector<TxReceiptPathStep>;
}

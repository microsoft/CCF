// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "kv/encryptor.h"

#include "crypto/symmetric_key.h"
#include "ledger_secrets.h"

namespace ccf
{
  using NodeEncryptor =
    kv::TxEncryptor<ccf::LedgerSecrets, crypto::GcmHeader<crypto::GCM_SIZE_IV>>;
}
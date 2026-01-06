// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/pem.h"
#include "ccf/ds/json.h"
#include "ccf/pal/attestation_sev_snp.h"

#include <cstdint>

namespace ccf
{
  enum DerivedSealingKeyAlgorithm : uint8_t
  {
    SNP_v1 = 0
  };

  DECLARE_JSON_ENUM(
    DerivedSealingKeyAlgorithm,
    {{DerivedSealingKeyAlgorithm::SNP_v1, "SNP_TCB_v1"}})

  struct SealedRecoveryKey
  {
    DerivedSealingKeyAlgorithm version;
    std::vector<uint8_t> ciphertext;
    crypto::Pem pubkey;
    pal::snp::TcbVersionRaw tcb_version;

    bool operator==(const SealedRecoveryKey&) const = default;
  };

  DECLARE_JSON_TYPE(SealedRecoveryKey);
  DECLARE_JSON_REQUIRED_FIELDS(
    SealedRecoveryKey, version, ciphertext, pubkey, tcb_version);
}
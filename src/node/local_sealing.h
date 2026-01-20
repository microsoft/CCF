// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/local_sealing.h"
#include "ccf/tx.h"
#include "node/ledger_secret.h"

namespace ccf::sealing
{
  const std::string LOCAL_SEALING_LABEL = "CCF AMD Local Sealing Key";

  std::vector<uint8_t> derive_snp_sealing_key(
    const ccf::pal::snp::TcbVersionRaw& tcb_version);

  SealedRecoveryKey get_snp_sealed_recovery_key(
    const pal::snp::TcbVersionRaw& tcb_version);

  void shuffle_sealed_shares(
    ccf::kv::Tx& tx, const LedgerSecretPtr& latest_ledger_secret);

  std::optional<LedgerSecretPtr> unseal_share(
    ccf::kv::ReadOnlyTx& tx, const NodeId& node_id);
}

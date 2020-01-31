// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include "Prepared_cert.h"
#include "View_change.h"
#include "consensus/pbft/pbftpreprepares.h"
#include "consensus/pbft/pbftrequests.h"
#include "consensus/pbft/pbfttypes.h"
#include "kv/kv.h"
#include "ledger.h"
#include "types.h"

class LedgerWriter
{
private:
  pbft::PbftStore& store;
  pbft::PrePreparesMap& pbft_pre_prepares_map;

public:
  LedgerWriter(
    pbft::PbftStore& store_, pbft::PrePreparesMap& pbft_pre_prepares_map_);
  virtual ~LedgerWriter() = default;
  void write_prepare(const Prepared_cert& prepared_cert, Seqno seqno);
  void write_pre_prepare(Pre_prepare* pp);
  void write_pre_prepare(ccf::Store::Tx& tx);
  void write_view_change(View_change* vc);
};

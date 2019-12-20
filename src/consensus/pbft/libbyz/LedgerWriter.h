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
  pbft::Store& store;
  pbft::PrePrepares& pbft_pre_prepares;

public:
  LedgerWriter(pbft::Store& store_, pbft::PrePrepares& pbft_pre_prepares_);
  virtual ~LedgerWriter() = default;
  void write_prepare(const Prepared_cert& prepared_cert, Seqno seqno);
  void write_pre_prepare(Pre_prepare* pp);
  void write_view_change(View_change* vc);
};

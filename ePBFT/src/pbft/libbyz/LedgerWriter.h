// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include "Prepared_cert.h"
#include "View_change.h"
#include "consensus/ledgerenclave.h"
#include "ledger.h"
#include "types.h"

class LedgerWriter
{
private:
  std::unique_ptr<consensus::LedgerEnclave> ledger;

public:
  LedgerWriter(std::unique_ptr<consensus::LedgerEnclave> ledger_);
  virtual ~LedgerWriter() = default;
  void write_prepare(const Prepared_cert& prepared_cert, Seqno seqno);
  void write_pre_prepare(Pre_prepare* pp);
  void write_view_change(View_change* vc);
  std::pair<std::vector<uint8_t>, bool> record_entry(
    const uint8_t*& data, size_t& size);
  void truncate(Seqno seqno);
};

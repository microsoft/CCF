// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include "Prepared_cert.h"
#include "View_change.h"
#include "ledger.h"
#include "types.h"

class LedgerWriter
{
public:
  typedef void (*append_ledger_entry_cb)(
    const uint8_t* data, size_t size, void* ctx);

private:
  // used to register a callback to write to the ledger
  append_ledger_entry_cb ledger_entry_cb;
  void* ledger_cb_ctx;

public:
  LedgerWriter(append_ledger_entry_cb ledger_entry_cb_, void* ledger_cb_ctx_);
  virtual ~LedgerWriter() = default;
  void write_prepare(const Prepared_cert& prepared_cert, Seqno seqno);
  void write_pre_prepare(Pre_prepare* pp);
  void write_view_change(View_change* vc);
};

// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once
#include "LedgerWriter.h"
#include "Message.h"
#include "Reply.h"
#include "Request.h"

class IMessageReceiveBase
{
public:
  IMessageReceiveBase() = default;
  virtual ~IMessageReceiveBase() = default;
  virtual void receive_message(const uint8_t* data, uint32_t size) = 0;
  typedef void (*reply_handler_cb)(Reply* m, void* ctx);
  virtual void register_reply_handler(reply_handler_cb cb, void* ctx) = 0;
  typedef void (*global_commit_handler_cb)(int64_t tx_ctx, void* cb_ctx);
  virtual void register_global_commit(
    global_commit_handler_cb cb, void* ctx) = 0;
  virtual void register_append_ledger_entry_cb(
    LedgerWriter::append_ledger_entry_cb append_ledger_entry, void* ctx) = 0;
  virtual size_t num_correct_replicas() const = 0;
  virtual size_t f() const = 0;
  virtual View view() const = 0;
  virtual bool is_primary() const = 0;
  virtual int primary() const = 0;
  virtual void handle(Request* m) = 0;
  virtual void send(Message* m, int i) = 0;
  virtual Seqno get_last_executed() const = 0;
};

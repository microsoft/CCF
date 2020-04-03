// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.
#pragma once
#include "ledger_writer.h"
#include "message.h"
#include "reply.h"
#include "request.h"

namespace pbft
{
  struct MarkStableInfo;
  struct GlobalCommitInfo;
  struct RollbackInfo;
}

class IMessageReceiveBase
{
public:
  IMessageReceiveBase() = default;
  virtual ~IMessageReceiveBase() = default;
  virtual void receive_message(const uint8_t* data, uint32_t size) = 0;
  typedef void (*reply_handler_cb)(Reply* m, void* ctx);
  virtual void register_reply_handler(reply_handler_cb cb, void* ctx) = 0;
  typedef void (*global_commit_handler_cb)(
    int64_t tx_ctx, View view, pbft::GlobalCommitInfo* cb_ctx);
  typedef void (*mark_stable_handler_cb)(pbft::MarkStableInfo* ms_info);
  virtual void register_global_commit(
    global_commit_handler_cb cb, pbft::GlobalCommitInfo* gb_info) = 0;
  virtual void register_mark_stable(
    mark_stable_handler_cb cb, pbft::MarkStableInfo* ms_info) = 0;
  typedef void (*rollback_handler_cb)(
    int64_t version, pbft::RollbackInfo* rollback_info);
  virtual void register_rollback_cb(
    rollback_handler_cb cb, pbft::RollbackInfo* ctx) = 0;
  virtual size_t num_correct_replicas() const = 0;
  virtual size_t f() const = 0;
  virtual void set_f(ccf::NodeId f) = 0;
  virtual View view() const = 0;
  virtual bool is_primary() const = 0;
  virtual int primary() const = 0;
  virtual void process_message(Message* m) = 0;
  virtual void send(Message* m, int i) = 0;
  virtual Seqno get_last_executed() const = 0;
  virtual int my_id() const = 0;
  virtual void emit_signature_on_next_pp(int64_t version) = 0;
  virtual void playback_pre_prepare(ccf::Store::Tx& tx) = 0;
  virtual void playback_request(ccf::Store::Tx& tx) = 0;
  virtual char* create_response_message(
    int client_id, Request_id rid, uint32_t size, uint64_t nonce) = 0;
  virtual bool IsExecutionPending() = 0;
};

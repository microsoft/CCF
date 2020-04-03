// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

/*
 * Definitions of various types.
 */

#include "consensus/pbft/pbft_types.h"
#include "parameters.h"

#include <array>
#include <cstdint>
#include <functional>

using Long = int64_t;
using ULong = uint64_t;

using Index = Long;
using Seqno = Long;
using View = Long;
using Request_id = ULong;

typedef struct sockaddr_in Addr;

static constexpr Long Long_max = std::numeric_limits<Long>::max();
static constexpr View View_max = std::numeric_limits<View>::max();
static constexpr Seqno Seqno_max = std::numeric_limits<Seqno>::max();

#include <bitset>
typedef std::bitset<Max_requests_in_batch> BR_map;

struct _Byz_buffer
{
  int size;
  char* contents;
  void* opaque;
};

typedef struct _Byz_buffer Byz_buffer;
typedef struct _Byz_buffer Byz_req;
typedef struct _Byz_buffer Byz_rep;

static const uint32_t MERKLE_ROOT_SIZE = 32;
struct ByzInfo
{
  std::array<uint8_t, MERKLE_ROOT_SIZE> replicated_state_merkle_root;
  int64_t ctx = INT64_MIN;
  void (*cb)(void* ctx) = nullptr;
  void* cb_ctx = nullptr;
  int64_t max_local_commit_value = INT64_MIN;
  uint32_t pending_cmd_callbacks;
  bool did_exec_gov_req;
  Seqno last_exec_gov_req;
};

class Request;
struct ExecCommandMsg;
struct ByzInfo;

struct ExecCommandMsg
{
  ExecCommandMsg(
    int client_,
    Request_id rid_,
    uint8_t* req_start_,
    size_t req_size_,
    bool include_merkle_roots_,
    Seqno total_requests_executed_,
    Seqno last_tentative_execute_,
    int64_t& max_local_commit_value_,
    int replier_,
    int reply_thread_,
    void (*cb_)(ExecCommandMsg& msg, ByzInfo& info),
    // if tx is nullptr we are in normal execution, otherwise we
    // are in playback mode
    ccf::Store::Tx* tx_ = nullptr) :
    client(client_),
    rid(rid_),
    req_start(req_start_),
    req_size(req_size_),
    include_merkle_roots(include_merkle_roots_),
    total_requests_executed(total_requests_executed_),
    last_tentative_execute(last_tentative_execute_),
    max_local_commit_value(max_local_commit_value_),
    replier(replier_),
    reply_thread(reply_thread_),
    cb(cb_),
    tx(tx_)
  {}

  Byz_req inb;
  Byz_rep outb;
  int client;
  Request_id rid;
  uint8_t* req_start;
  size_t req_size;
  bool include_merkle_roots;
  Seqno total_requests_executed;
  int reply_thread;
  ccf::Store::Tx* tx;

  // Required for the callback
  Seqno last_tentative_execute;
  int64_t& max_local_commit_value;
  int replier;
  void (*cb)(ExecCommandMsg& msg, ByzInfo& info);
};

using ExecCommand = std::function<int(
  std::array<std::unique_ptr<ExecCommandMsg>, Max_requests_in_batch>& msgs,
  ByzInfo&,
  uint32_t,
  uint64_t)>;
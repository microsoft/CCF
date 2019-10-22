// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include "Big_req_table.h"
#include "LedgerWriter.h"
#include "Req_queue.h"
#include "types.h"

#include <memory>
#include <unordered_map>
#include <vector>

class LedgerReplay
{
private:
  std::unique_ptr<Pre_prepare> latest_pre_prepare;

public:
  virtual ~LedgerReplay() = default;
  template <typename T>
  std::unique_ptr<T> create_message(
    const uint8_t* message_data, size_t data_size);
  std::vector<std::unique_ptr<Pre_prepare>> process_data(
    const std::vector<uint8_t>& data,
    Req_queue& rqueue,
    Big_req_table& brt,
    LedgerWriter& ledger_writed,
    Seqno last_executed);
  void clear_requests(Req_queue& rqueue, Big_req_table& brt);
};
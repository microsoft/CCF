// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "LedgerReplay.h"

#include "Request.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "ledger.h"

LedgerReplay::LedgerReplay(size_t total_ledger_len_) :
  total_ledger_len(total_ledger_len_)
{}

template <class T>
std::unique_ptr<T> LedgerReplay::create_message(
  const uint8_t* message_data, size_t data_size)
{
  Message* m = new Message(Max_message_size);
  memcpy(m->contents(), message_data, data_size);
  T* msg_type;
  T::convert(m, msg_type);
  return std::unique_ptr<T>(msg_type);
}

size_t LedgerReplay::cursor() const
{
  return total_ledger_len;
}

std::unique_ptr<Pre_prepare> LedgerReplay::process_data(
  const std::vector<uint8_t>& data,
  Req_queue& rqueue,
  Big_req_table& brt,
  LedgerWriter* ledger_writer)
{
  PBFT_ASSERT(
    !data.empty(), "apply ledger data should not receive empty vector");

  // received a new entry so we have read the entry size from the file
  total_ledger_len += sizeof(size_t);

  auto entry_data = data.data();
  auto data_size = data.size();
  total_ledger_len += data_size;

  // peek at header type
  Ledger_header_type type =
    *reinterpret_cast<Ledger_header_type*>(const_cast<uint8_t*>(entry_data));

  if (type == Ledger_header_type::Pre_prepare_ledger_header)
  {
    auto header =
      serialized::overlay<Pre_prepare_ledger_header>(entry_data, data_size);
    latest_pre_prepare = create_message<Pre_prepare>(entry_data, data_size);
  }
  else if (type == Ledger_header_type::Pre_prepare_ledger_large_message_header)
  {
    auto header = serialized::overlay<Pre_prepare_ledger_large_message_header>(
      entry_data, data_size);

    auto req =
      create_message<Request>(entry_data, header.message_size).release();

    if (!(req->size() > Request::big_req_thresh && brt.add_request(req)))
    {
      rqueue.append(req);
    }
  }

  auto pre_prepare = latest_pre_prepare.get();

  Pre_prepare::Requests_iter iter(pre_prepare);
  // check that all big requests are present
  Request request;
  bool is_request_present = false;
  while (iter.get_big_request(request, is_request_present))
  {
    if (!is_request_present)
    {
      return nullptr;
    }
  }

  if (!is_request_present && rqueue.size() == 0)
  {
    return nullptr;
  }
  return std::move(latest_pre_prepare);
}
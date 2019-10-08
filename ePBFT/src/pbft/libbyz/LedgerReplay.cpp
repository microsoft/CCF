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

void LedgerReplay::apply_data(
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
    LOG_INFO << "Received Pre prepare header: " << header.sequence_num
             << std::endl;
    latest_pre_prepare = create_message<Pre_prepare>(entry_data, data_size);
  }
  else if (type == Ledger_header_type::Pre_prepare_ledger_large_message_header)
  {
    auto header = serialized::overlay<Pre_prepare_ledger_large_message_header>(
      entry_data, data_size);
    LOG_INFO << "Received large message header: " << header.message_size
             << std::endl;

    auto req = create_message<Request>(entry_data, data_size).release();

    if (!(req->size() > Request::big_req_thresh && brt.add_request(req)))
    {
      rqueue.append(req);
    }
  }

  // TODO process requests here
  Pre_prepare::Requests_iter iter(latest_pre_prepare.get());
  // check that all big requests are present
  Request request;
  bool is_request_present = false;
  while (iter.get_big_request(request, is_request_present))
  {
    if (!is_request_present)
    {
      return;
    }
  }

  if (ledger_writer)
  {
    ledger_writer->write_pre_prepare(latest_pre_prepare.get());
  }
}

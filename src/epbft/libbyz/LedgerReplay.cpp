// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "LedgerReplay.h"

#include "Request.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "ledger.h"

// TODO (#pbft) add replay for prepares and view changes
// https://github.com/microsoft/CCF/issues/459

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

std::vector<std::unique_ptr<Pre_prepare>> LedgerReplay::process_data(
  const std::vector<uint8_t>& data,
  Req_queue& rqueue,
  Big_req_table& brt,
  LedgerWriter& ledger_writer,
  Seqno last_executed)
{
  auto entry_data = data.data();
  auto data_size = data.size();

  std::vector<std::unique_ptr<Pre_prepare>> pre_prepares;

  while (data_size > 0)
  {
    auto ret = ledger_writer.record_entry(entry_data, data_size);

    if (!ret.second)
    {
      PBFT_ASSERT(
        ret.second,
        "record entry should successfully record data into the ledger");
      // NB: This will currently never be triggered.
      // This should only fail if there is malformed data. Truncate
      // the log and reply false.
      LOG_FAIL << "record entry failed, truncating to last executed: "
               << last_executed << std::endl;
      ledger_writer.truncate(last_executed);
      return {};
    }

    const std::vector<uint8_t>& ret_vector = ret.first;
    auto e_data = ret_vector.data();
    auto e_size = ret_vector.size();

    auto type = serialized::peek<Ledger_header_type>(e_data, e_size);

    if (type == Ledger_header_type::Pre_prepare_ledger_header)
    {
      auto header =
        serialized::overlay<Pre_prepare_ledger_header>(e_data, e_size);
      latest_pre_prepare =
        create_message<Pre_prepare>(e_data, header.message_size);
      serialized::skip(e_data, e_size, header.message_size);
      if (latest_pre_prepare->num_big_reqs() > 0)
      {
        for (size_t i = 0; i < latest_pre_prepare->num_big_reqs(); ++i)
        {
          auto header =
            serialized::overlay<Pre_prepare_ledger_large_message_header>(
              e_data, e_size);

          auto req =
            create_message<Request>(e_data, header.message_size).release();

          serialized::skip(e_data, e_size, header.message_size);
          if (!(req->size() > Request::big_req_thresh && brt.add_request(req)))
          {
            rqueue.append(req);
          }
        }
      }
    }

    auto pre_prepare = latest_pre_prepare.get();

    Pre_prepare::Requests_iter iter(pre_prepare);
    // check that all big requests are present
    // TODO remove looping over requests again here
    Request request;
    bool is_request_present = false;
    while (iter.get_big_request(request, is_request_present))
    {
      if (!is_request_present)
      {
        continue;
      }
    }

    if (!is_request_present && rqueue.size() == 0)
    {
      continue;
    }
    pre_prepares.push_back(std::move(latest_pre_prepare));
  }
  return pre_prepares;
}

void LedgerReplay::clear_requests(Req_queue& rqueue, Big_req_table& brt)
{
  rqueue.clear();
  brt.clear();
}
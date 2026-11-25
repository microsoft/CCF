// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/cft_types.h"
#include "ds/serialized.h"
#include "host/ledger_subsystem.h"
#include "node/node_types.h"

#include <functional>

namespace asynchost
{
  // Both transports assemble complete frames after preceding ledger mutations.
  // Wire format: [u32 frame size][msg type][sender ID][payload][entries].
  inline void send_node_frame(
    Ledger& ledger,
    LedgerSubsystem& ledger_subsystem,
    const ccf::NodeId& to,
    ccf::NodeMsgType msg_type,
    const ccf::NodeId& from,
    std::vector<uint8_t>&& payload,
    std::function<void(std::vector<uint8_t>&&)> deliver)
  {
    if (
      !ledger_subsystem.run_in_mutation_order(
        "Node send",
        [&ledger,
         to,
         msg_type,
         from,
         payload = std::move(payload),
         deliver = std::move(deliver)]() {
          const auto& from_value = from.value();
          std::vector<uint8_t> header(
            sizeof(msg_type) + sizeof(size_t) + from_value.size());
          {
            auto* hdata = header.data();
            auto hsize = header.size();
            serialized::write(hdata, hsize, msg_type);
            serialized::write(hdata, hsize, from_value);
          }

          const uint8_t* data = payload.data();
          size_t size = payload.size();

          std::vector<uint8_t> entries;
          std::optional<::consensus::AppendEntriesIndex> ae_index;

          if (
            msg_type == ccf::NodeMsgType::consensus_msg &&
            (serialized::read<aft::CftMsgType>(data, size) ==
             aft::append_entries))
          {
            const auto& ae =
              serialized::overlay<::consensus::AppendEntriesIndex>(data, size);
            ae_index = ae;

            if (ae.idx > ae.prev_idx)
            {
              std::optional<LedgerReadResult> read_result =
                ledger.read_entries(ae.prev_idx + 1, ae.idx);

              if (!read_result.has_value())
              {
                LOG_FAIL_FMT(
                  "Unable to send AppendEntries ({}, {}]: Ledger read failed",
                  ae.prev_idx,
                  ae.idx);
                return;
              }

              if (ae.idx != read_result->end_idx)
              {
                // No max_size was passed to read_entries.
                LOG_FAIL_FMT(
                  "Unable to send AppendEntries ({}, {}]: Ledger read returned "
                  "entries to {}",
                  ae.prev_idx,
                  ae.idx,
                  read_result->end_idx);
                return;
              }

              entries = std::move(read_result->data);
            }
          }

          const auto frame_size = static_cast<uint32_t>(
            header.size() + payload.size() + entries.size());
          std::vector<uint8_t> frame;
          frame.reserve(sizeof(frame_size) + frame_size);
          frame.insert(
            frame.end(),
            reinterpret_cast<const uint8_t*>(&frame_size),
            reinterpret_cast<const uint8_t*>(&frame_size) + sizeof(frame_size));
          frame.insert(frame.end(), header.begin(), header.end());
          frame.insert(frame.end(), payload.begin(), payload.end());
          frame.insert(frame.end(), entries.begin(), entries.end());

          if (ae_index.has_value())
          {
            LOG_DEBUG_FMT(
              "send AE to node {} [{}]: {}, {}",
              to,
              frame_size,
              ae_index->idx,
              ae_index->prev_idx);
          }
          else
          {
            LOG_DEBUG_FMT("node send to {} [{}]", to, frame_size);
          }

          deliver(std::move(frame));
        }))
    {
      LOG_DEBUG_FMT("Dropping Node send because the host is shutting down");
    }
  }
}

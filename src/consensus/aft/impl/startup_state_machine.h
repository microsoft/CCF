// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/aft_types.h"
#include "consensus/ledger_enclave.h"
#include "ds/ccf_exception.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "request_message.h"
#include "status_message.h"
#include "request_data_message.h"



#include <vector>

namespace aft
{
  class IStartupStateMachine
  {
  public:
    IStartupStateMachine() = default;
    virtual ~IStartupStateMachine() = default;

    virtual kv::Version receive_request(std::unique_ptr<RequestMessage> request) = 0;
    virtual void receive_message(OArray&& oa, kv::NodeId from) = 0;
    virtual void receive_message(OArray&& oa, AppendEntries ae, kv::NodeId from) = 0;
  };

  class StartupStateMachine : public IStartupStateMachine
  {
  public:
    StartupStateMachine(std::shared_ptr<EnclaveNetwork> network_, IStore& store_) :
      network(network_), store(store_), is_first_message(true), have_requested_data(false)
    {}
    virtual ~StartupStateMachine() = default;

    kv::Version receive_request(std::unique_ptr<RequestMessage> request) override
    {
      // TODO: the network is not open so we will execute everything inline
      // TODO: check that we are running on thread 0 - we do not want
      // multi-threading before the network is open

      std::shared_ptr<enclave::RpcContext>& ctx = request->get_request_ctx().ctx;
      std::shared_ptr<enclave::RpcHandler>& frontend = request->get_request_ctx().frontend;

      ctx->pbft_raw.resize(request->size());
      request->serialize_message(ctx->pbft_raw.data(), ctx->pbft_raw.size());

      ctx->is_create_request = is_first_message;
      ctx->set_apply_writes(true);

      enclave::RpcHandler::ProcessPbftResp rep = frontend->process_pbft(ctx);

      frontend->update_merkle_tree();

      is_first_message = false;
      request->callback(rep.result);

      return rep.version;
    }

    void receive_message(OArray&& oa, kv::NodeId from) override
    {
      LOG_INFO_FMT("Received message from:{}, tag:{}", from, get_message_type(oa.data()));

      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
          handle_status_message(std::move(oa), from);
          break;
        case MessageTag::RequestData:
          handle_request_data_message(std::move(oa), from);
          break;
        default:
          CCF_ASSERT_FMT_FAIL("Unknown or unsupported message type - {}", get_message_type(oa.data()));
      }
    }

    void receive_message(OArray&& oa, AppendEntries ae, kv::NodeId from) override
    {
      const uint8_t* data = oa.data();
      size_t size = oa.size();

      for (ccf::Index i = ae.prev_idx; i < ae.idx; i++)
      {
        // TODO: this should not be commented out!!!!!
        /*
        append_entries_index = store->current_version();
        LOG_TRACE_FMT("Recording entry for index {}", i);

        if (i <= append_entries_index)
        {
          // If the current entry has already been deserialised, skip the
          // payload for that entry
          LOG_INFO_FMT(
            "Skipping index {} as we are at index {}", i, append_entries_index);
          ledger->skip_entry(data, size);
          continue;
        }
        LOG_TRACE_FMT("Applying append entry for index {}", i);
        */

        std::vector<uint8_t> entry;
        try
        {
          entry = consensus::LedgerEnclave::get_entry(data, size);
        }
        catch (const std::logic_error& e)
        {
          // This should only fail if there is malformed data.
          LOG_FAIL_FMT(
            "Recv append entries to {} from {} at entry {} but the data is "
            "malformed: {}",
            network->get_my_node_id(),
            ae.from_node,
            i,
            e.what());
          return;
        }

        kv::Tx tx;
        auto deserialise_success =
          store.deserialise_views(entry, false, nullptr, &tx);

        switch (deserialise_success)
        {
          case kv::DeserialiseSuccess::PASS:
            LOG_INFO_FMT("deserialized entry, i - {}", i);
            //message_receiver_base->playback_request(tx);
            break;
          default:
            CCF_ASSERT_FMT_FAIL("Invalid entry type {}", deserialise_success);
        }
      }
    }

    private:
      std::shared_ptr<EnclaveNetwork> network;
      IStore& store;
      bool is_first_message;
      bool have_requested_data;
      kv::Version last_received_version = 0;

      void handle_status_message(OArray && oa, kv::NodeId from)
      {
        if (have_requested_data)
        {
          // We have already requested data so need to do that again
          return;
        }

        StatusMessageRecv status(std::move(oa), from);

        RequestDataMessage request(
          last_received_version,
          std::min(status.get_version(), last_received_version + 100));
        network->Send(request, from);
      }

      void handle_request_data_message(OArray && oa, kv::NodeId from)
      {
        RequestDataMessageRecv request(std::move(oa), from);

        kv::Version index_from = request.get_from();
        kv::Version index_to = request.get_to();

        AppendEntries ae = {
          aft_append_entries, network->get_my_node_id(), index_to, index_from};
        network->Send(ae, from);
      }
    };
  }
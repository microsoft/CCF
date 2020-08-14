// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/aft/aft_network.h"
#include "consensus/aft/aft_types.h"
#include "consensus/aft/request.h"
#include "consensus/ledger_enclave.h"
#include "consensus/pbft/pbft_requests.h"
#include "ds/ccf_exception.h"
#include "enclave/rpc_map.h"
#include "http/http_rpc_context.h"
#include "kv/kv_types.h"
#include "kv/tx.h"
#include "request_data_message.h"
#include "request_message.h"
#include "status_message.h"

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
    virtual kv::Version receive_message(OArray&& oa, AppendEntries ae, kv::NodeId from) = 0;
  };

  class StartupStateMachine : public IStartupStateMachine
  {
  public:
    StartupStateMachine(
      std::shared_ptr<EnclaveNetwork> network_,
      std::shared_ptr<enclave::RPCMap> rpc_map_,
      IStore& store_,
      pbft::RequestsMap& pbft_requests_map_) :
      network(network_),
      rpc_map(rpc_map_),
      store(store_),
      pbft_requests_map(pbft_requests_map_),
      is_first_message(true),
      have_requested_data(false)
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

    kv::Version receive_message(OArray&& oa, AppendEntries ae, kv::NodeId from) override
    {
      const uint8_t* data = oa.data();
      size_t size = oa.size();
      kv::Version last_version = kv::NoVersion;
      kv::Version version;

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
          return last_version;
        }

        kv::Tx tx;
        auto deserialise_success =
          store.deserialise_views(entry, false, nullptr, &tx);

        switch (deserialise_success)
        {
          case kv::DeserialiseSuccess::PASS:
            LOG_INFO_FMT("deserialized entry, i - {}", i);
            version = commit_replayed_request(tx);
            last_version = std::max(version, last_version);


            //message_receiver_base->playback_request(tx);
            break;
          default:
            CCF_ASSERT_FMT_FAIL("Invalid entry type {}", deserialise_success);
        }
      }
      return last_version;
    }

    kv::Version commit_replayed_request(kv::Tx& tx)
    {
      auto tx_view = tx.get_view(pbft_requests_map);
      auto req_v = tx_view->get(0);
      CCF_ASSERT(
        req_v.has_value(),
        "Deserialised request but it was not found in the requests map");
      pbft::Request request = req_v.value();

      //auto ctx = create_request_ctx(request.raw.data(), request.raw.size());
      auto ctx = create_request_ctx(request);

      auto request_message = RequestMessage::deserialize(
        request.pbft_raw.data(), request.pbft_raw.size(), std::move(ctx), nullptr);
      return receive_request(std::move(request_message));

      /*
            auto request_message = std::make_unique<RequestMessage>(
              request.raw(),
              args.rid,
              std::move(ctx),
              nullptr;
            );
      */

      //auto req =
      //  create_message<Request>(request.pbft_raw.data(), request.pbft_raw.size());
      //req->create_context(verify_command);
    }

  private:
    std::shared_ptr<EnclaveNetwork> network;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    IStore& store;
    bool is_first_message;
    bool have_requested_data;
    kv::Version last_received_version = 0;
    pbft::RequestsMap& pbft_requests_map;

    void handle_status_message(OArray&& oa, kv::NodeId from)
    {
      if (have_requested_data)
      {
        // We have already requested data so need to do that again
        return;
      }
      have_requested_data = true;

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
        kv::Version index_to = request.get_to() + 1;

        LOG_INFO_FMT("Sending entries {} to {}", index_from, index_to);

        AppendEntries ae = {
          aft_append_entries, network->get_my_node_id(), index_to, index_from};
        network->Send(ae, from);
      }

      // TODO: this is duplicated 
      std::unique_ptr<RequestCtx> create_request_ctx(
        //uint8_t* req_start, size_t req_size)
        pbft::Request& request)
      {
        //LOG_INFO_FMT("Deserailizing {}", req_size);
        auto r_ctx = std::make_unique<RequestCtx>();
        //Request request;
        //request.deserialise(req_start, req_size);

        auto session = std::make_shared<enclave::SessionContext>(
          enclave::InvalidSessionId, request.caller_id, request.caller_cert);

        r_ctx->ctx = enclave::make_fwd_rpc_context(
          session, request.raw, (enclave::FrameFormat)request.frame_format);

        const auto actor_opt = http::extract_actor(*r_ctx->ctx);
        if (!actor_opt.has_value())
        {
          throw std::logic_error(fmt::format(
            "Failed to extract actor from PBFT request. Method is '{}'",
            r_ctx->ctx->get_method()));
        }

        const auto& actor_s = actor_opt.value();
        std::string preferred_actor_s;
        const auto actor = rpc_map->resolve(actor_s, preferred_actor_s);
        auto handler = rpc_map->find(actor);
        if (!handler.has_value())
          throw std::logic_error(
            fmt::format("No frontend associated with actor {}", actor_s));

        r_ctx->frontend = handler.value();
        return r_ctx;
      };
  };
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "startup_state_machine.h"

#include "consensus/aft/aft_network.h"
#include "consensus/aft/request.h"
#include "consensus/ledger_enclave.h"
#include "consensus/pbft/pbft_requests.h"
#include "ds/ccf_exception.h"
#include "enclave/rpc_map.h"
#include "http/http_rpc_context.h"
#include "kv/tx.h"
#include "request_data_message.h"
#include "request_message.h"
#include "status_message.h"

#include <vector>

namespace aft
{
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
      last_version(kv::NoVersion)
    {}
    virtual ~StartupStateMachine() = default;

    kv::Version receive_request(std::unique_ptr<RequestMessage> request) override
    {
      CCF_ASSERT(
        threading::get_current_thread_id() ==
          threading::ThreadMessaging::main_thread,
        "Should be executed on the main thread");

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

      last_version = rep.version;
      return rep.version;
    }

    bool receive_message(OArray& oa, kv::NodeId from) override
    {
      CCF_ASSERT(
        threading::get_current_thread_id() ==
          threading::ThreadMessaging::main_thread,
        "Should be executed on the main thread");

      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
          handle_status_message(std::move(oa), from);
          break;
        case MessageTag::RequestData:
          handle_request_data_message(std::move(oa), from);
          break;
        default:
          CCF_ASSERT_FMT_FAIL("Unsupported msg type {}", get_message_type(oa.data()));
          return false;
      }
      return true;
    }

    bool is_message_type_supported(OArray& oa) override
    {
      switch (get_message_type(oa.data()))
      {
        case MessageTag::Status:
        case MessageTag::RequestData:
          return true;
        default:
          return false;
      }
    }

    kv::Version receive_message(OArray& oa, AppendEntries ae, kv::NodeId from) override
    {
      CCF_ASSERT(
        threading::get_current_thread_id() ==
          threading::ThreadMessaging::main_thread,
        "Should be executed on the main thread");

      const uint8_t* data = oa.data();
      size_t size = oa.size();
      kv::Version version;

      LOG_INFO_FMT("Applying entries from {}, total {}, size {}", from, ae.idx, oa.size());

      for (ccf::Index i = ae.prev_idx; i < ae.idx; i++)
      {
        if (i < last_version)
        {
          // If the current entry has already been deserialised, skip the
          // payload for that entry
          LOG_INFO_FMT(
            "Skipping index {} as we are at index {}", i, last_version);
          consensus::LedgerEnclave::skip_entry(data, size);
          continue;
        }
        LOG_TRACE_FMT("Applying append entry for index {}", i);

        std::vector<uint8_t> entry;
        try
        {
          entry = consensus::LedgerEnclave::get_entry(data, size);
        }
        catch (const std::logic_error& e)
        {
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
            version = commit_replayed_request(tx);
            last_version = std::max(version, last_version);
            LOG_INFO_FMT("deserialized view i - {}, from {}", i, from);
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

      auto ctx = create_request_ctx(request);

      auto request_message = RequestMessage::deserialize(
        request.pbft_raw.data(), request.pbft_raw.size(), std::move(ctx), nullptr);
      return receive_request(std::move(request_message));
    }

  private:
    std::shared_ptr<EnclaveNetwork> network;
    std::shared_ptr<enclave::RPCMap> rpc_map;
    IStore& store;
    bool is_first_message;
    pbft::RequestsMap& pbft_requests_map;
    kv::Version last_version = kv::NoVersion;

    void handle_status_message(OArray&& oa, kv::NodeId from)
    {
      StatusMessageRecv status(std::move(oa), from);
      LOG_INFO_FMT("****** last {}, status {}", last_version, status.get_version());
      if (last_version > status.get_version())
      {
        // We have already requested data so need to do that again
        return;
      }

      RequestDataMessage request(
        std::max(last_version, (int64_t)0), status.get_version());
      network->Send(request, from);
      }

      void handle_request_data_message(OArray && oa, kv::NodeId from)
      {
        RequestDataMessageRecv request(std::move(oa), from);

        kv::Version index_from = request.get_from();
        kv::Version index_to = request.get_to();

        LOG_INFO_FMT("Sending entries {} to {}, to node {}", index_from, index_to, from);

        AppendEntries ae = {
          aft_append_entries, network->get_my_node_id(), index_to, index_from};
        network->Send(ae, from);
      }

      std::unique_ptr<RequestCtx> create_request_ctx(
        pbft::Request& request)
      {
        auto r_ctx = std::make_unique<RequestCtx>();

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
      }
  };

  std::unique_ptr<IStartupStateMachine> create_startup_state_machine(
    std::shared_ptr<EnclaveNetwork> network,
    std::shared_ptr<enclave::RPCMap> rpc_map,
    IStore& store,
    pbft::RequestsMap& pbft_requests_map)
  {
    return std::make_unique<StartupStateMachine>(
      network, rpc_map, store, pbft_requests_map);
  }
}
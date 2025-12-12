// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/app_interface.h"
#include "ccf/js/core/context.h"
#include "ccf/node_context.h"
#include "ccf/node_subsystem_interface.h"
#include "ccf/pal/mem.h"
#include "crypto/openssl/hash.h"
#include "ds/internal_logger.h"
#include "ds/oversized.h"
#include "ds/work_beacon.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/historical_transaction_fetcher.h"
#include "interface.h"
#include "js/interpreter_cache.h"
#include "kv/ledger_chunker.h"
#include "node/commit_callback_subsystem.h"
#include "node/historical_queries.h"
#include "node/network_state.h"
#include "node/node_state.h"
#include "node/node_types.h"
#include "node/rpc/cosesigconfig_subsystem.h"
#include "node/rpc/custom_protocol_subsystem.h"
#include "node/rpc/forwarder.h"
#include "node/rpc/gov_effects.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/network_identity_subsystem.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/node_operation.h"
#include "node/rpc/user_frontend.h"
#include "rpc_map.h"
#include "rpc_sessions.h"

#include <openssl/engine.h>

namespace ccf
{
  class Enclave
  {
  private:
    std::unique_ptr<ringbuffer::Circuit> circuit;
    std::unique_ptr<ringbuffer::WriterFactory> basic_writer_factory;
    std::unique_ptr<oversized::WriterFactory> writer_factory;
    ccf::ds::WorkBeaconPtr work_beacon;
    ccf::NetworkState network;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RPCSessions> rpcsessions;
    std::unique_ptr<ccf::NodeState> node;
    ringbuffer::WriterPtr to_host = nullptr;
    std::chrono::high_resolution_clock::time_point last_tick_time;
    std::atomic<bool> worker_stop_signal = false;

    StartType start_type{};

    struct NodeContext : public ccf::AbstractNodeContext
    {
      const ccf::NodeId this_node;

      NodeContext(ccf::NodeId id) : this_node(std::move(id)) {}

      [[nodiscard]] ccf::NodeId get_node_id() const override
      {
        return this_node;
      }
    };

    std::unique_ptr<NodeContext> context = nullptr;

    std::shared_ptr<ccf::historical::StateCache> historical_state_cache =
      nullptr;
    std::shared_ptr<ccf::indexing::Indexer> indexer = nullptr;
    std::shared_ptr<ccf::indexing::EnclaveLFSAccess> lfs_access = nullptr;

  public:
    Enclave(
      std::unique_ptr<ringbuffer::Circuit> circuit_,
      std::unique_ptr<ringbuffer::WriterFactory> basic_writer_factory_,
      std::unique_ptr<oversized::WriterFactory> writer_factory_,
      size_t sig_tx_interval,
      size_t sig_ms_interval,
      size_t chunk_threshold,
      const ccf::consensus::Configuration& consensus_config,
      const ccf::crypto::CurveID& curve_id,
      ccf::ds::WorkBeaconPtr work_beacon_) :
      circuit(std::move(circuit_)),
      basic_writer_factory(std::move(basic_writer_factory_)),
      writer_factory(std::move(writer_factory_)),
      work_beacon(std::move(work_beacon_)),
      rpc_map(std::make_shared<RPCMap>()),
      rpcsessions(std::make_shared<RPCSessions>(*writer_factory, rpc_map))
    {
      to_host = writer_factory->create_writer_to_outside();

      LOG_TRACE_FMT("Creating ledger secrets");
      network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();

      network.tables->set_chunker(
        std::make_shared<ccf::kv::LedgerChunker>(chunk_threshold));

      LOG_TRACE_FMT("Creating node");
      node = std::make_unique<ccf::NodeState>(
        *writer_factory, network, rpcsessions, curve_id);

      LOG_TRACE_FMT("Creating context");
      context = std::make_unique<NodeContext>(node->get_node_id());

      LOG_TRACE_FMT("Creating context subsystems");
      historical_state_cache = std::make_shared<ccf::historical::StateCache>(
        *network.tables,
        network.ledger_secrets,
        writer_factory->create_writer_to_outside());
      context->install_subsystem(historical_state_cache);

      indexer = std::make_shared<ccf::indexing::Indexer>(
        std::make_shared<ccf::indexing::HistoricalTransactionFetcher>(
          historical_state_cache));
      context->install_subsystem(indexer);

      lfs_access = std::make_shared<ccf::indexing::EnclaveLFSAccess>(
        writer_factory->create_writer_to_outside());
      context->install_subsystem(lfs_access);

      context->install_subsystem(std::make_shared<ccf::NodeOperation>(*node));
      context->install_subsystem(
        std::make_shared<ccf::GovernanceEffects>(*node));

      context->install_subsystem(
        std::make_shared<ccf::NetworkIdentitySubsystem>(
          *node, network.identity, historical_state_cache));

      context->install_subsystem(
        std::make_shared<ccf::NodeConfigurationSubsystem>(*node));

      auto cpss = std::make_shared<ccf::CustomProtocolSubsystem>(*node);
      context->install_subsystem(cpss);
      rpcsessions->set_custom_protocol_subsystem(cpss);

      static constexpr size_t max_interpreter_cache_size = 10;
      auto interpreter_cache =
        std::make_shared<ccf::js::InterpreterCache>(max_interpreter_cache_size);
      context->install_subsystem(interpreter_cache);

      context->install_subsystem(
        std::make_shared<ccf::AbstractCOSESignaturesConfigSubsystem>(*node));

      auto commit_callbacks = std::make_shared<ccf::CommitCallbackSubsystem>();
      context->install_subsystem(commit_callbacks);
      rpcsessions->set_commit_callbacks_subsystem(commit_callbacks);

      LOG_TRACE_FMT("Creating RPC actors / ffi");
      rpc_map->register_frontend<ccf::ActorsType::members>(
        std::make_unique<ccf::MemberRpcFrontend>(network, *context));

      rpc_map->register_frontend<ccf::ActorsType::users>(
        std::make_unique<ccf::UserRpcFrontend>(
          network, ccf::make_user_endpoints(*context), *context));

      rpc_map->register_frontend<ccf::ActorsType::nodes>(
        std::make_unique<ccf::NodeRpcFrontend>(network, *context));

      LOG_TRACE_FMT("Initialize node");
      node->initialize(
        consensus_config,
        rpc_map,
        rpcsessions,
        indexer,
        commit_callbacks,
        sig_tx_interval,
        sig_ms_interval);
    }

    ~Enclave()
    {
      LOG_TRACE_FMT("Shutting down enclave");
    }

    CreateNodeStatus create_new_node(
      StartType start_type_,
      const ccf::StartupConfig& ccf_config_,
      std::vector<uint8_t>&& startup_snapshot,
      std::vector<uint8_t>& node_cert,
      std::vector<uint8_t>& service_cert)
    {
      start_type = start_type_;

      rpcsessions->update_listening_interface_options(ccf_config_.network);

      node->set_n2n_message_limit(ccf_config_.node_to_node_message_limit);

      historical_state_cache->set_soft_cache_limit(
        ccf_config_.historical_cache_soft_limit);

      // If we haven't heard from a node for multiple elections, then cleanup
      // their node-to-node channel
      const auto idle_timeout =
        std::chrono::milliseconds(ccf_config_.consensus.election_timeout) * 4;
      node->set_n2n_idle_timeout(idle_timeout);

      ccf::NodeCreateInfo create_info;
      try
      {
        LOG_TRACE_FMT(
          "Creating node with start_type {}", start_type_to_str(start_type));
        create_info =
          node->create(start_type, ccf_config_, std::move(startup_snapshot));
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Error starting node: {}", e.what());
        return CreateNodeStatus::InternalError;
      }

      // Copy node and service certs out
      node_cert = create_info.self_signed_node_cert.raw();

      if (start_type == StartType::Start || start_type == StartType::Recover)
      {
        // When starting a node in start or recover modes, fresh network secrets
        // are created and the associated certificate can be passed to the host
        service_cert = create_info.service_cert.raw();
      }

      return CreateNodeStatus::OK;
    }

    bool run_main()
    {
      LOG_DEBUG_FMT("Running main thread");

      {
        messaging::BufferProcessor bp("Enclave");

        // reconstruct oversized messages sent to the enclave
        oversized::FragmentReconstructor fr(bp.get_dispatcher());

        lfs_access->register_message_handlers(bp.get_dispatcher());

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::stop, [this, &bp](const uint8_t*, size_t) {
            bp.set_finished();
            this->worker_stop_signal.store(true);
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::stop_notice, [this](const uint8_t*, size_t) {
            node->stop_notice();
          });

        last_tick_time = decltype(last_tick_time)::clock::now();

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          AdminMessage::tick,
          [this, &disp = bp.get_dispatcher()](const uint8_t*, size_t) {
            const auto message_counts = disp.retrieve_message_counts();
            const auto j = disp.convert_message_counts(message_counts);
            RINGBUFFER_WRITE_MESSAGE(
              AdminMessage::work_stats, to_host, j.dump());

            const auto time_now = decltype(last_tick_time)::clock::now();

            const auto elapsed_ms =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                time_now - last_tick_time);
            if (elapsed_ms.count() > 0)
            {
              last_tick_time += elapsed_ms;

              node->tick(elapsed_ms);
              historical_state_cache->tick(elapsed_ms);
              ccf::tasks::tick(elapsed_ms);
              // When recovering, no signature should be emitted while the
              // public ledger is being read
              if (!node->is_reading_public_ledger())
              {
                for (auto& [actor, frontend] : rpc_map->frontends())
                {
                  frontend->tick(elapsed_ms);
                }
              }
              node->tick_end();
            }
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, ccf::node_inbound, [this](const uint8_t* data, size_t size) {
            try
            {
              node->recv_node_inbound(data, size);
            }
            catch (const std::exception& e)
            {
              LOG_DEBUG_FMT(
                "Ignoring node_inbound message due to exception: {}", e.what());
            }
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          ::consensus::ledger_entry_range,
          [this](const uint8_t* data, size_t size) {
            const auto [from_seqno, to_seqno, purpose, body] =
              ringbuffer::read_message<::consensus::ledger_entry_range>(
                data, size);
            switch (purpose)
            {
              case ::consensus::LedgerRequestPurpose::Recovery:
              {
                if (node->is_reading_public_ledger())
                {
                  node->recover_public_ledger_entries(body);
                }
                else if (node->is_reading_private_ledger())
                {
                  node->recover_private_ledger_entries(body);
                }
                else
                {
                  auto [s, _, __] = node->state();
                  LOG_FAIL_FMT(
                    "Cannot recover ledger entry: Unexpected node state {}", s);
                }
                break;
              }
              case ::consensus::LedgerRequestPurpose::HistoricalQuery:
              {
                historical_state_cache->handle_ledger_entries(
                  from_seqno, to_seqno, body);
                break;
              }
              default:
              {
                LOG_FAIL_FMT("Unhandled purpose: {}", purpose);
              }
            }
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          ::consensus::ledger_no_entry_range,
          [this](const uint8_t* data, size_t size) {
            const auto [from_seqno, to_seqno, purpose] =
              ringbuffer::read_message<::consensus::ledger_no_entry_range>(
                data, size);
            switch (purpose)
            {
              case ::consensus::LedgerRequestPurpose::Recovery:
              {
                node->recover_ledger_end();
                break;
              }
              case ::consensus::LedgerRequestPurpose::HistoricalQuery:
              {
                historical_state_cache->handle_no_entry_range(
                  from_seqno, to_seqno);
                break;
              }
              default:
              {
                LOG_FAIL_FMT("Unhandled purpose: {}", purpose);
              }
            }
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          ::consensus::snapshot_allocated,
          [this](const uint8_t* data, size_t size) {
            const auto [snapshot_span, generation_count] =
              ringbuffer::read_message<::consensus::snapshot_allocated>(
                data, size);

            node->write_snapshot(snapshot_span, generation_count);
          });

        rpcsessions->register_message_handlers(bp.get_dispatcher());

        // Maximum number of inbound ringbuffer messages which will be
        // processed in a single iteration
        static constexpr size_t max_messages = 256;

        while (!bp.get_finished())
        {
          // Wait until the host indicates that some ringbuffer messages are
          // available, but wake at least every 100ms to check thread messages
          work_beacon->wait_for_work_with_timeout(
            std::chrono::milliseconds(100));

          // First, read some messages from the ringbuffer
          auto read = bp.read_n(max_messages, circuit->read_from_outside());

          // Then, execute some tasks
          auto& job_board = ccf::tasks::get_main_job_board();
          ccf::tasks::Task task = job_board.get_task();
          size_t tasks_done = 0;
          while (task != nullptr)
          {
            task->do_task();
            ++tasks_done;
            if (tasks_done >= max_messages)
            {
              break;
            }
            task = job_board.get_task();
          }

          // If no messages were read from the ringbuffer and tasks were
          // executed, idle
          if (read == 0 && tasks_done == 0)
          {
            std::this_thread::yield();
          }
        }

        LOG_INFO_FMT("Enclave stopped successfully. Stopping host...");
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::stopped, to_host);

        return true;
      }
    }

    bool run_worker()
    {
      LOG_DEBUG_FMT("Running worker thread");

      {
        auto& job_board = ccf::tasks::get_main_job_board();
        const auto timeout = std::chrono::milliseconds(100);

        while (!worker_stop_signal.load())
        {
          auto task = job_board.wait_for_task(timeout);
          if (task != nullptr)
          {
            task->do_task();
          }
        }
      }

      return true;
    }
  };
}

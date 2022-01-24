// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/app_interface.h"
#include "crypto/hash.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "enclave_time.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/historical_transaction_fetcher.h"
#include "interface.h"
#include "js/wrap.h"
#include "node/entities.h"
#include "node/historical_queries.h"
#include "node/network_state.h"
#include "node/node_state.h"
#include "node/node_types.h"
#include "node/rpc/forwarder.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/node_frontend.h"
#include "oe_init.h"
#include "rpc_map.h"
#include "rpc_sessions.h"

#include <openssl/engine.h>

namespace enclave
{
  class Enclave
  {
  private:
    std::unique_ptr<ringbuffer::Circuit> circuit;
    std::unique_ptr<ringbuffer::WriterFactory> basic_writer_factory;
    std::unique_ptr<oversized::WriterFactory> writer_factory;
    ccf::NetworkState network;
    ccf::ShareManager share_manager;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RPCSessions> rpcsessions;
    std::unique_ptr<ccf::NodeState> node;
    ringbuffer::WriterPtr to_host = nullptr;
    std::chrono::microseconds last_tick_time;
    ENGINE* rdrand_engine = nullptr;

    StartType start_type;

    struct NodeContext : public ccfapp::AbstractNodeContext
    {
      std::shared_ptr<ccf::historical::StateCache> historical_state_cache =
        nullptr;
      ccf::AbstractNodeState* node_state = nullptr;
      std::shared_ptr<ccf::indexing::Indexer> indexer = nullptr;
      std::unique_ptr<ccf::indexing::EnclaveLFSAccess> lfs_access = nullptr;

      NodeContext() {}

      ccf::historical::AbstractStateCache& get_historical_state() override
      {
        if (historical_state_cache == nullptr)
        {
          throw std::logic_error(
            "Calling get_historical_state before NodeContext is initialized");
        }
        return *historical_state_cache;
      }

      ccf::AbstractNodeState& get_node_state() override
      {
        if (node_state == nullptr)
        {
          throw std::logic_error(
            "Calling get_node_state before NodeContext is initialized");
        }
        return *node_state;
      }

      ccf::indexing::IndexingStrategies& get_indexing_strategies() override
      {
        if (indexer == nullptr)
        {
          throw std::logic_error(
            "Calling get_indexing_strategies before NodeContext is "
            "initialized");
        }
        return *indexer;
      }

      ccf::indexing::AbstractLFSAccess& get_lfs_access() override
      {
        if (lfs_access == nullptr)
        {
          throw std::logic_error(
            "Calling get_lfs_access before NodeContext is "
            "initialized");
        }
        return *lfs_access;
      }
    };

    std::unique_ptr<NodeContext> context = nullptr;

  public:
    Enclave(
      const EnclaveConfig& ec,
      std::unique_ptr<ringbuffer::Circuit> circuit_,
      std::unique_ptr<ringbuffer::WriterFactory> basic_writer_factory_,
      std::unique_ptr<oversized::WriterFactory> writer_factory_,
      size_t sig_tx_interval,
      size_t sig_ms_interval,
      const consensus::Configuration& consensus_config,
      const CurveID& curve_id) :
      circuit(std::move(circuit_)),
      basic_writer_factory(std::move(basic_writer_factory_)),
      writer_factory(std::move(writer_factory_)),
      network(consensus_config.type),
      share_manager(network),
      rpc_map(std::make_shared<RPCMap>()),
      rpcsessions(std::make_shared<RPCSessions>(*writer_factory, rpc_map))
    {
      ccf::initialize_oe();

      // From
      // https://software.intel.com/content/www/us/en/develop/articles/how-to-use-the-rdrand-engine-in-openssl-for-random-number-generation.html
      if (
        ENGINE_load_rdrand() != 1 ||
        (rdrand_engine = ENGINE_by_id("rdrand")) == nullptr ||
        ENGINE_init(rdrand_engine) != 1 ||
        ENGINE_set_default(rdrand_engine, ENGINE_METHOD_RAND) != 1)
      {
        LOG_FAIL_FMT("Error creating OpenSSL's RDRAND engine");
        ENGINE_free(rdrand_engine);
        throw ccf::ccf_openssl_rdrand_init_error(
          "could not initialize RDRAND engine for OpenSSL");
      }

      to_host = writer_factory->create_writer_to_outside();

      LOG_TRACE_FMT("Creating ledger secrets");
      network.ledger_secrets = std::make_shared<ccf::LedgerSecrets>();

      LOG_TRACE_FMT("Creating node");
      node = std::make_unique<ccf::NodeState>(
        *writer_factory, network, rpcsessions, share_manager, curve_id);

      LOG_TRACE_FMT("Creating context");
      context = std::make_unique<NodeContext>();
      context->historical_state_cache =
        std::make_shared<ccf::historical::StateCache>(
          *network.tables,
          network.ledger_secrets,
          writer_factory->create_writer_to_outside());
      context->node_state = node.get();
      context->indexer = std::make_shared<ccf::indexing::Indexer>(
        std::make_shared<ccf::indexing::HistoricalTransactionFetcher>(
          context->historical_state_cache));
      context->lfs_access = std::make_unique<ccf::indexing::EnclaveLFSAccess>(
        writer_factory->create_writer_to_outside());

      LOG_TRACE_FMT("Creating RPC actors / ffi");
      rpc_map->register_frontend<ccf::ActorsType::members>(
        std::make_unique<ccf::MemberRpcFrontend>(
          network, *context, share_manager));

      rpc_map->register_frontend<ccf::ActorsType::users>(
        ccfapp::get_rpc_handler(network, *context));

      rpc_map->register_frontend<ccf::ActorsType::nodes>(
        std::make_unique<ccf::NodeRpcFrontend>(network, *context));

      ccf::js::register_ffi_plugins(ccfapp::get_js_plugins());

      LOG_TRACE_FMT("Initialize node");
      node->initialize(
        consensus_config,
        rpc_map,
        rpcsessions,
        context->indexer,
        sig_tx_interval,
        sig_ms_interval);
    }

    ~Enclave()
    {
      if (rdrand_engine)
      {
        LOG_TRACE_FMT("Finishing RDRAND engine");
        ENGINE_finish(rdrand_engine);
        ENGINE_free(rdrand_engine);
      }
      LOG_TRACE_FMT("Shutting down enclave");
      ccf::shutdown_oe();
    }

    CreateNodeStatus create_new_node(
      StartType start_type_,
      StartupConfig&& ccf_config_,
      uint8_t* node_cert,
      size_t node_cert_size,
      size_t* node_cert_len,
      uint8_t* service_cert,
      size_t service_cert_size,
      size_t* service_cert_len)
    {
      // node_cert_size and service_cert_size are ignored here, but we pass them
      // in because it allows us to set EDL an annotation so that node_cert_len
      // <= node_cert_size is checked by the EDL-generated wrapper

      start_type = start_type_;

      rpcsessions->update_listening_interface_caps(ccf_config_.network);

      ccf::NodeCreateInfo r;
      try
      {
        LOG_TRACE_FMT(
          "Creating node with start_type {}", start_type_to_str(start_type));
        r = node->create(start_type, std::move(ccf_config_));
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("Error starting node: {}", e.what());
        return CreateNodeStatus::InternalError;
      }

      // Copy node and service certs out
      if (r.self_signed_node_cert.size() > node_cert_size)
      {
        LOG_FAIL_FMT(
          "Insufficient space ({}) to copy node_cert out ({})",
          node_cert_size,
          r.self_signed_node_cert.size());
        return CreateNodeStatus::InternalError;
      }
      ::memcpy(
        node_cert,
        r.self_signed_node_cert.data(),
        r.self_signed_node_cert.size());
      *node_cert_len = r.self_signed_node_cert.size();

      if (start_type == StartType::Start || start_type == StartType::Recover)
      {
        // When starting a node in start or recover modes, fresh network secrets
        // are created and the associated certificate can be passed to the host
        if (r.service_cert.size() > service_cert_size)
        {
          LOG_FAIL_FMT(
            "Insufficient space ({}) to copy service_cert out ({})",
            service_cert_size,
            r.service_cert.size());
          return CreateNodeStatus::InternalError;
        }
        ::memcpy(service_cert, r.service_cert.data(), r.service_cert.size());
        *service_cert_len = r.service_cert.size();
      }

      return CreateNodeStatus::OK;
    }

    bool run_main()
    {
      LOG_DEBUG_FMT("Running main thread");
#ifndef VIRTUAL_ENCLAVE
      try
#endif
      {
        messaging::BufferProcessor bp("Enclave");

        // reconstruct oversized messages sent to the enclave
        oversized::FragmentReconstructor fr(bp.get_dispatcher());

        context->lfs_access->register_message_handlers(bp.get_dispatcher());

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::stop, [&bp](const uint8_t*, size_t) {
            bp.set_finished();
            threading::ThreadMessaging::thread_messaging.set_finished();
          });

        last_tick_time = enclave::get_enclave_time();

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          AdminMessage::tick,
          [this, &disp = bp.get_dispatcher()](const uint8_t*, size_t) {
            const auto message_counts = disp.retrieve_message_counts();
            const auto j = disp.convert_message_counts(message_counts);
            RINGBUFFER_WRITE_MESSAGE(
              AdminMessage::work_stats, to_host, j.dump());

            const auto time_now = enclave::get_enclave_time();
            logger::config::set_time(time_now);

            const auto elapsed_ms =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                time_now - last_tick_time);
            if (elapsed_ms.count() > 0)
            {
              last_tick_time = time_now;

              node->tick(elapsed_ms);
              context->historical_state_cache->tick(elapsed_ms);
              threading::ThreadMessaging::thread_messaging.tick(elapsed_ms);
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
            node->recv_node_inbound(data, size);
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          consensus::ledger_entry_range,
          [this](const uint8_t* data, size_t size) {
            const auto [from_seqno, to_seqno, purpose, body] =
              ringbuffer::read_message<consensus::ledger_entry_range>(
                data, size);
            switch (purpose)
            {
              case consensus::LedgerRequestPurpose::Recovery:
              {
                if (from_seqno != to_seqno)
                {
                  LOG_FAIL_FMT(
                    "Unexpected range for Recovery response "
                    "ledger_entry_range: {}->{} "
                    "(expected single ledger entry)",
                    from_seqno,
                    to_seqno);
                }
                if (
                  node->is_reading_public_ledger() ||
                  node->is_verifying_snapshot())
                {
                  node->recover_public_ledger_entry(body);
                }
                else if (node->is_reading_private_ledger())
                {
                  node->recover_private_ledger_entry(body);
                }
                else
                {
                  auto [s, _, __] = node->state();
                  LOG_FAIL_FMT(
                    "Cannot recover ledger entry: Unexpected node state {}", s);
                }
                break;
              }
              case consensus::LedgerRequestPurpose::HistoricalQuery:
              {
                context->historical_state_cache->handle_ledger_entries(
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
          consensus::ledger_no_entry_range,
          [this](const uint8_t* data, size_t size) {
            const auto [from_seqno, to_seqno, purpose] =
              ringbuffer::read_message<consensus::ledger_no_entry_range>(
                data, size);
            switch (purpose)
            {
              case consensus::LedgerRequestPurpose::Recovery:
              {
                if (from_seqno != to_seqno)
                {
                  LOG_FAIL_FMT(
                    "Unexpected range for Recovery response "
                    "ledger_no_entry_range: {}->{} "
                    "(expected single ledger entry)",
                    from_seqno,
                    to_seqno);
                }
                if (node->is_verifying_snapshot())
                {
                  node->verify_snapshot_end();
                }
                else
                {
                  node->recover_ledger_end();
                }
                break;
              }
              case consensus::LedgerRequestPurpose::HistoricalQuery:
              {
                context->historical_state_cache->handle_no_entry_range(
                  from_seqno, to_seqno);
                break;
              }
              default:
              {
                LOG_FAIL_FMT("Unhandled purpose: {}", purpose);
              }
            }
          });

        rpcsessions->register_message_handlers(bp.get_dispatcher());

        if (start_type == StartType::Join)
        {
          // When joining from a snapshot, deserialise ledger suffix to verify
          // snapshot evidence. Otherwise, attempt to join straight away
          if (node->is_verifying_snapshot())
          {
            node->start_ledger_recovery();
          }
          else
          {
            node->join();
          }
        }
        else if (start_type == StartType::Recover)
        {
          node->start_ledger_recovery();
        }

        // Maximum number of inbound ringbuffer messages which will be
        // processed in a single iteration
        static constexpr size_t max_messages = 256;

        size_t consecutive_idles = 0u;
        while (!bp.get_finished())
        {
          // First, read some messages from the ringbuffer
          auto read = bp.read_n(max_messages, circuit->read_from_outside());

          // Then, execute some thread messages
          size_t thread_msg = 0;
          while (thread_msg < max_messages &&
                 threading::ThreadMessaging::thread_messaging.run_one())
          {
            thread_msg++;
          }

          // If no messages were read from the ringbuffer and no thread
          // messages were executed, idle
          if (read == 0 && thread_msg == 0)
          {
            const auto time_now = enclave::get_enclave_time();
            static std::chrono::microseconds idling_start_time;

            if (consecutive_idles == 0)
            {
              idling_start_time = time_now;
            }

            // Handle initial idles by pausing, eventually sleep (in host)
            constexpr std::chrono::milliseconds timeout(5);
            if ((time_now - idling_start_time) > timeout)
            {
              std::this_thread::sleep_for(timeout * 10);
            }
            else
            {
              CCF_PAUSE();
            }

            consecutive_idles++;
          }
          else
          {
            // If some messages were read, reset consecutive idles count
            consecutive_idles = 0;
          }
        }

        LOG_INFO_FMT("Enclave stopped successfully. Stopping host...");
        RINGBUFFER_WRITE_MESSAGE(AdminMessage::stopped, to_host);

        return true;
      }
#ifndef VIRTUAL_ENCLAVE
      catch (const std::exception& e)
      {
        // It is expected that all enclave modules consuming ring buffer
        // messages catch any thrown exception they can recover from. Uncaught
        // exceptions bubble up to here and cause the node to shutdown.
        RINGBUFFER_WRITE_MESSAGE(
          AdminMessage::fatal_error_msg, to_host, std::string(e.what()));
        return false;
      }
#endif
    }

    struct Msg
    {
      uint64_t tid;
    };

    static void init_thread_cb(std::unique_ptr<threading::Tmsg<Msg>> msg)
    {
      LOG_DEBUG_FMT("First thread CB:{}", msg->data.tid);
    }

    bool run_worker()
    {
      LOG_DEBUG_FMT("Running worker thread");
#ifndef VIRTUAL_ENCLAVE
      try
#endif
      {
        auto msg = std::make_unique<threading::Tmsg<Msg>>(&init_thread_cb);
        msg->data.tid = threading::get_current_thread_id();
        threading::ThreadMessaging::thread_messaging.add_task(
          msg->data.tid, std::move(msg));

        threading::ThreadMessaging::thread_messaging.run();
      }
#ifndef VIRTUAL_ENCLAVE
      catch (const std::exception& e)
      {
        RINGBUFFER_WRITE_MESSAGE(
          AdminMessage::fatal_error_msg, to_host, std::string(e.what()));
        return false;
      }
#endif
      return true;
    }
  };
}

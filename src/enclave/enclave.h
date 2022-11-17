// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "ccf/app_interface.h"
#include "ccf/ds/logger.h"
#include "ccf/pal/enclave.h"
#include "ccf/pal/mem.h"
#include "ds/oversized.h"
#include "enclave_time.h"
#include "indexing/enclave_lfs_access.h"
#include "indexing/historical_transaction_fetcher.h"
#include "interface.h"
#include "js/wrap.h"
#include "node/acme_challenge_frontend.h"
#include "node/historical_queries.h"
#include "node/network_state.h"
#include "node/node_state.h"
#include "node/node_types.h"
#include "node/rpc/acme_subsystem.h"
#include "node/rpc/forwarder.h"
#include "node/rpc/gov_effects.h"
#include "node/rpc/host_processes.h"
#include "node/rpc/member_frontend.h"
#include "node/rpc/network_identity_subsystem.h"
#include "node/rpc/node_frontend.h"
#include "node/rpc/node_operation.h"
#include "node/rpc/user_frontend.h"
#include "ringbuffer_logger.h"
#include "rpc_map.h"
#include "rpc_sessions.h"
#include "verify.h"

#include <openssl/engine.h>

namespace ccf
{
  class Enclave
  {
  private:
    std::unique_ptr<ringbuffer::Circuit> circuit;
    std::unique_ptr<ringbuffer::WriterFactory> basic_writer_factory;
    std::unique_ptr<oversized::WriterFactory> writer_factory;
    RingbufferLogger* ringbuffer_logger = nullptr;
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
      const ccf::NodeId this_node;

      NodeContext(const ccf::NodeId& id) : this_node(id) {}

      ccf::NodeId get_node_id() const override
      {
        return this_node;
      }
    };

    std::unique_ptr<NodeContext> context = nullptr;

    std::shared_ptr<ccf::historical::StateCache> historical_state_cache =
      nullptr;
    std::shared_ptr<ccf::indexing::Indexer> indexer = nullptr;
    std::shared_ptr<ccf::indexing::EnclaveLFSAccess> lfs_access = nullptr;
    std::shared_ptr<ccf::HostProcesses> host_processes = nullptr;

  public:
    Enclave(
      std::unique_ptr<ringbuffer::Circuit> circuit_,
      std::unique_ptr<ringbuffer::WriterFactory> basic_writer_factory_,
      std::unique_ptr<oversized::WriterFactory> writer_factory_,
      RingbufferLogger* ringbuffer_logger_,
      size_t sig_tx_interval,
      size_t sig_ms_interval,
      const consensus::Configuration& consensus_config,
      const crypto::CurveID& curve_id) :
      circuit(std::move(circuit_)),
      basic_writer_factory(std::move(basic_writer_factory_)),
      writer_factory(std::move(writer_factory_)),
      ringbuffer_logger(ringbuffer_logger_),
      network(consensus_config.type),
      share_manager(network),
      rpc_map(std::make_shared<RPCMap>()),
      rpcsessions(std::make_shared<RPCSessions>(*writer_factory, rpc_map))
    {
      ccf::pal::initialize_enclave();
      ccf::initialize_verifiers();

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

      context->install_subsystem(std::make_shared<ccf::HostProcesses>(*node));
      context->install_subsystem(std::make_shared<ccf::NodeOperation>(*node));
      context->install_subsystem(
        std::make_shared<ccf::GovernanceEffects>(*node));

      context->install_subsystem(
        std::make_shared<ccf::NetworkIdentitySubsystem>(
          *node, network.identity));

      context->install_subsystem(
        std::make_shared<ccf::NodeConfigurationSubsystem>(*node));

      context->install_subsystem(std::make_shared<ccf::ACMESubsystem>(*node));

      context->install_subsystem(rpcsessions);

      LOG_TRACE_FMT("Creating RPC actors / ffi");
      rpc_map->register_frontend<ccf::ActorsType::members>(
        std::make_unique<ccf::MemberRpcFrontend>(
          network, *context, share_manager));

      rpc_map->register_frontend<ccf::ActorsType::users>(
        std::make_unique<ccf::UserRpcFrontend>(
          network, ccfapp::make_user_endpoints(*context), *context));

      rpc_map->register_frontend<ccf::ActorsType::nodes>(
        std::make_unique<ccf::NodeRpcFrontend>(network, *context));

      // Note: for ACME challenges, the well-known frontend should really only
      // listen on the interface specified in the ACMEClientConfig, but we don't
      // have support for frontends restricted to particular interfaces yet.
      rpc_map->register_frontend<ccf::ActorsType::well_known>(
        std::make_unique<ccf::ACMERpcFrontend>(network, *context));

      ccf::js::register_ffi_plugins(ccfapp::get_js_plugins());

      LOG_TRACE_FMT("Initialize node");
      node->initialize(
        consensus_config,
        rpc_map,
        rpcsessions,
        indexer,
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
      ccf::shutdown_verifiers();
      ccf::pal::shutdown_enclave();
    }

    CreateNodeStatus create_new_node(
      StartType start_type_,
      StartupConfig&& ccf_config_,
      std::vector<uint8_t>&& startup_snapshot,
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

      rpcsessions->update_listening_interface_options(ccf_config_.network);

      ccf::NodeCreateInfo r;
      try
      {
        LOG_TRACE_FMT(
          "Creating node with start_type {}", start_type_to_str(start_type));
        r = node->create(
          start_type, std::move(ccf_config_), std::move(startup_snapshot));
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
      pal::safe_memcpy(
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
        pal::safe_memcpy(
          service_cert, r.service_cert.data(), r.service_cert.size());
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

        lfs_access->register_message_handlers(bp.get_dispatcher());

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::stop, [&bp](const uint8_t*, size_t) {
            bp.set_finished();
            threading::ThreadMessaging::thread_messaging.set_finished();
          });

        last_tick_time = ccf::get_enclave_time();

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          AdminMessage::tick,
          [this, &disp = bp.get_dispatcher()](const uint8_t*, size_t) {
            const auto message_counts = disp.retrieve_message_counts();
            const auto j = disp.convert_message_counts(message_counts);
            RINGBUFFER_WRITE_MESSAGE(
              AdminMessage::work_stats, to_host, j.dump());

            const auto time_now = ccf::get_enclave_time();
            ringbuffer_logger->set_time(time_now);

            const auto elapsed_ms =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                time_now - last_tick_time);
            if (elapsed_ms.count() > 0)
            {
              last_tick_time += elapsed_ms;

              node->tick(elapsed_ms);
              historical_state_cache->tick(elapsed_ms);
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
              case consensus::LedgerRequestPurpose::HistoricalQuery:
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
                node->recover_ledger_end();
                break;
              }
              case consensus::LedgerRequestPurpose::HistoricalQuery:
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

        rpcsessions->register_message_handlers(bp.get_dispatcher());

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
            const auto time_now = ccf::get_enclave_time();
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

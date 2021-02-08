// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "app_interface.h"
#include "crypto/hash.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "enclave_time.h"
#include "interface.h"
#include "node/entities.h"
#include "node/historical_queries.h"
#include "node/network_state.h"
#include "node/node_state.h"
#include "node/node_types.h"
#include "node/rpc/forwarder.h"
#include "node/rpc/node_frontend.h"
#include "rpc_map.h"
#include "rpc_sessions.h"

#include <openssl/engine.h>

namespace enclave
{
  class Enclave
  {
  private:
    ringbuffer::Circuit circuit;
    ringbuffer::WriterFactory basic_writer_factory;
    oversized::WriterFactory writer_factory;
    ccf::NetworkState network;
    ccf::ShareManager share_manager;
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RPCSessions> rpcsessions;
    std::unique_ptr<ccf::NodeState> node;
    std::shared_ptr<ccf::Forwarder<ccf::NodeToNode>> cmd_forwarder;
    ringbuffer::WriterPtr to_host = nullptr;
    std::chrono::milliseconds last_tick_time;
    ENGINE* rdrand_engine = nullptr;

    CCFConfig ccf_config;
    StartType start_type;

    struct NodeContext : public ccfapp::AbstractNodeContext
    {
      ccf::historical::StateCache historical_state_cache;
      ccf::AbstractNodeState* node_state = nullptr;

      NodeContext(ccf::historical::StateCache&& hsc) :
        historical_state_cache(std::move(hsc))
      {}

      ccf::historical::AbstractStateCache& get_historical_state() override
      {
        return historical_state_cache;
      }

      ccf::AbstractNodeState& get_node_state() override
      {
        return *node_state;
      }
    } context;

  public:
    Enclave(
      const EnclaveConfig& ec,
      const CCFConfig::SignatureIntervals& signature_intervals,
      const ConsensusType& consensus_type_,
      const consensus::Configuration& consensus_config,
      const CurveID& curve_id) :
      circuit(
        ringbuffer::BufferDef{ec.to_enclave_buffer_start,
                              ec.to_enclave_buffer_size,
                              ec.to_enclave_buffer_offsets},
        ringbuffer::BufferDef{ec.from_enclave_buffer_start,
                              ec.from_enclave_buffer_size,
                              ec.from_enclave_buffer_offsets}),
      basic_writer_factory(circuit),
      writer_factory(basic_writer_factory, ec.writer_config),
      network(consensus_type_),
      share_manager(network),
      n2n_channels(std::make_shared<ccf::NodeToNodeImpl>(writer_factory)),
      rpc_map(std::make_shared<RPCMap>()),
      rpcsessions(std::make_shared<RPCSessions>(writer_factory, rpc_map)),
      cmd_forwarder(std::make_shared<ccf::Forwarder<ccf::NodeToNode>>(
        rpcsessions, n2n_channels, rpc_map, consensus_type_)),
      context(ccf::historical::StateCache(
        *network.tables, writer_factory.create_writer_to_outside()))
    {
      logger::config::msg() = AdminMessage::log_msg;
      logger::config::writer() = writer_factory.create_writer_to_outside();

      to_host = writer_factory.create_writer_to_outside();

      node = std::make_unique<ccf::NodeState>(
        writer_factory, network, rpcsessions, share_manager, curve_id);
      context.node_state = node.get();

      rpc_map->register_frontend<ccf::ActorsType::members>(
        std::make_unique<ccf::MemberRpcFrontend>(
          network, *node, share_manager));

      rpc_map->register_frontend<ccf::ActorsType::users>(
        ccfapp::get_rpc_handler(network, context));

      rpc_map->register_frontend<ccf::ActorsType::nodes>(
        std::make_unique<ccf::NodeRpcFrontend>(network, *node));

      for (auto& [actor, fe] : rpc_map->frontends())
      {
        fe->set_sig_intervals(
          signature_intervals.sig_tx_interval,
          signature_intervals.sig_ms_interval);
        fe->set_cmd_forwarder(cmd_forwarder);
      }

      node->initialize(
        consensus_config,
        n2n_channels,
        rpc_map,
        cmd_forwarder,
        signature_intervals.sig_tx_interval,
        signature_intervals.sig_ms_interval);
    }

    ~Enclave()
    {
      if (rdrand_engine)
      {
        ENGINE_finish(rdrand_engine);
        ENGINE_free(rdrand_engine);
      }
    }

    bool create_new_node(
      StartType start_type_,
      const CCFConfig& ccf_config_,
      uint8_t* node_cert,
      size_t node_cert_size,
      size_t* node_cert_len,
      uint8_t* network_cert,
      size_t network_cert_size,
      size_t* network_cert_len)
    {
      // node_cert_size and network_cert_size are ignored here, but we pass them
      // in because it allows us to set EDL an annotation so that node_cert_len
      // <= node_cert_size is checked by the EDL-generated wrapper

      start_type = start_type_;
      ccf_config = ccf_config_;

      // From
      // https://software.intel.com/content/www/us/en/develop/articles/how-to-use-the-rdrand-engine-in-openssl-for-random-number-generation.html
      if (
        ENGINE_load_rdrand() != 1 ||
        (rdrand_engine = ENGINE_by_id("rdrand")) == nullptr ||
        ENGINE_init(rdrand_engine) != 1 ||
        ENGINE_set_default(rdrand_engine, ENGINE_METHOD_RAND) != 1)
        throw std::runtime_error(
          "could not initialize RDRAND engine for OpenSSL");

      ccf::NodeCreateInfo r;
      try
      {
        r = node->create(start_type, ccf_config);
      }
      catch (const std::runtime_error& e)
      {
        LOG_FAIL_FMT("Error starting node: {}", e.what());
        return false;
      }

      // Copy node and network certs out
      if (r.node_cert.size() > node_cert_size)
      {
        LOG_FAIL_FMT(
          "Insufficient space ({}) to copy node_cert out ({})",
          node_cert_size,
          r.node_cert.size());
        return false;
      }
      ::memcpy(node_cert, r.node_cert.data(), r.node_cert.size());
      *node_cert_len = r.node_cert.size();

      if (start_type == StartType::New || start_type == StartType::Recover)
      {
        // When starting a node in start or recover modes, fresh network secrets
        // are created and the associated certificate can be passed to the host
        if (r.network_cert.size() > network_cert_size)
        {
          LOG_FAIL_FMT(
            "Insufficient space ({}) to copy network_cert out ({})",
            network_cert_size,
            r.network_cert.size());
          return false;
        }
        ::memcpy(network_cert, r.network_cert.data(), r.network_cert.size());
        *network_cert_len = r.network_cert.size();
      }

      return true;
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

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::stop, [&bp](const uint8_t*, size_t) {
            bp.set_finished();
            threading::ThreadMessaging::thread_messaging.set_finished();
          });

        last_tick_time = std::chrono::duration_cast<std::chrono::milliseconds>(
          enclave::get_enclave_time());

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::tick, [this, &bp](const uint8_t*, size_t) {
            const auto message_counts =
              bp.get_dispatcher().retrieve_message_counts();
            const auto j =
              bp.get_dispatcher().convert_message_counts(message_counts);
            RINGBUFFER_WRITE_MESSAGE(
              AdminMessage::work_stats, to_host, j.dump());

            const auto time_now =
              std::chrono::duration_cast<std::chrono::milliseconds>(
                enclave::get_enclave_time());
            logger::config::set_time(time_now);

            std::chrono::milliseconds elapsed_ms = time_now - last_tick_time;
            if (elapsed_ms.count() > 0)
            {
              last_tick_time = time_now;

              node->tick(elapsed_ms);
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
            const auto [body] =
              ringbuffer::read_message<ccf::node_inbound>(data, size);

            auto p = body.data();
            auto psize = body.size();

            if (
              serialized::peek<ccf::NodeMsgType>(p, psize) ==
              ccf::NodeMsgType::forwarded_msg)
            {
              cmd_forwarder->recv_message(p, psize);
            }
            else
            {
              node->node_msg(std::move(body));
            }
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          consensus::ledger_entry,
          [this](const uint8_t* data, size_t size) {
            const auto [index, purpose, body] =
              ringbuffer::read_message<consensus::ledger_entry>(data, size);
            switch (purpose)
            {
              case consensus::LedgerRequestPurpose::Recovery:
              {
                if (
                  node->is_reading_public_ledger() ||
                  node->is_verifying_snapshot())
                  node->recover_public_ledger_entry(body);
                else if (node->is_reading_private_ledger())
                  node->recover_private_ledger_entry(body);
                else
                  LOG_FAIL_FMT("Cannot recover ledger entry: Unexpected state");
                break;
              }
              case consensus::LedgerRequestPurpose::HistoricalQuery:
              {
                context.historical_state_cache.handle_ledger_entry(index, body);
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
          consensus::ledger_no_entry,
          [this](const uint8_t* data, size_t size) {
            const auto [index, purpose] =
              ringbuffer::read_message<consensus::ledger_no_entry>(data, size);
            switch (purpose)
            {
              case consensus::LedgerRequestPurpose::Recovery:
              {
                if (node->is_verifying_snapshot())
                {
                  node->verify_snapshot_end(ccf_config);
                }
                else
                {
                  node->recover_ledger_end();
                }
                break;
              }
              case consensus::LedgerRequestPurpose::HistoricalQuery:
              {
                context.historical_state_cache.handle_no_entry(index);
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
          if (!ccf_config.startup_snapshot.empty())
          {
            node->start_ledger_recovery();
          }
          else
          {
            node->join(ccf_config);
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
          auto read = bp.read_n(max_messages, circuit.read_from_outside());

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

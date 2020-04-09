// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "app_interface.h"
#include "crypto/hash.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "interface.h"
#include "node/entities.h"
#include "node/network_state.h"
#include "node/node_state.h"
#include "node/nodetypes.h"
#include "node/notifier.h"
#include "node/rpc/forwarder.h"
#include "node/rpc/node_frontend.h"
#include "node/timer.h"
#include "rpc_map.h"
#include "rpc_sessions.h"

namespace enclave
{
  class Enclave
  {
  private:
    ringbuffer::Circuit* circuit;
    ringbuffer::WriterFactory basic_writer_factory;
    oversized::WriterFactory writer_factory;
    ccf::NetworkState network;
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    ccf::Notifier notifier;
    ccf::Timers timers;
    std::shared_ptr<RPCMap> rpc_map;
    std::shared_ptr<RPCSessions> rpcsessions;
    ccf::NodeState node;
    std::shared_ptr<ccf::Forwarder<ccf::NodeToNode>> cmd_forwarder;

    CCFConfig ccf_config;
    StartType start_type;
    ConsensusType consensus_type;

  public:
    Enclave(
      EnclaveConfig* enclave_config,
      const CCFConfig::SignatureIntervals& signature_intervals,
      const ConsensusType& consensus_type_,
      const consensus::Config& consensus_config) :
      circuit(enclave_config->circuit),
      basic_writer_factory(*circuit),
      writer_factory(basic_writer_factory, enclave_config->writer_config),
      network(consensus_type_),
      n2n_channels(std::make_shared<ccf::NodeToNode>(writer_factory)),
      notifier(writer_factory),
      rpc_map(std::make_shared<RPCMap>()),
      rpcsessions(std::make_shared<RPCSessions>(writer_factory, rpc_map)),
      node(writer_factory, network, rpcsessions, notifier, timers),
      cmd_forwarder(std::make_shared<ccf::Forwarder<ccf::NodeToNode>>(
        rpcsessions, n2n_channels, rpc_map)),
      consensus_type(consensus_type_)
    {
      logger::config::msg() = AdminMessage::log_msg;
      logger::config::writer() = writer_factory.create_writer_to_outside();

      REGISTER_FRONTEND(
        rpc_map,
        members,
        std::make_unique<ccf::MemberRpcFrontend>(network, node));

      REGISTER_FRONTEND(
        rpc_map, users, ccfapp::get_rpc_handler(network, notifier));

      REGISTER_FRONTEND(
        rpc_map, nodes, std::make_unique<ccf::NodeRpcFrontend>(network, node));

      for (auto& [actor, fe] : rpc_map->get_map())
      {
        fe->set_sig_intervals(
          signature_intervals.sig_max_tx, signature_intervals.sig_max_ms);
        fe->set_cmd_forwarder(cmd_forwarder);
      }

      node.initialize(consensus_config, n2n_channels, rpc_map, cmd_forwarder);
    }

    bool create_new_node(
      StartType start_type_,
      const CCFConfig& ccf_config_,
      uint8_t* node_cert,
      size_t node_cert_size,
      size_t* node_cert_len,
      uint8_t* network_cert,
      size_t network_cert_size,
      size_t* network_cert_len,
      uint8_t* network_enc_pubk,
      size_t network_enc_pubk_size,
      size_t* network_enc_pubk_len)
    {
      // node_cert_size and network_cert_size are ignored here, but we pass them
      // in because it allows us to set EDL an annotation so that node_cert_len
      // <= node_cert_size is checked by the EDL-generated wrapper

      start_type = start_type_;
      ccf_config = ccf_config_;

      auto r = node.create({start_type, ccf_config});
      if (!r.second)
        return false;

      // Copy node and network certs out
      if (r.first.node_cert.size() > node_cert_size)
      {
        LOG_FAIL_FMT(
          "Insufficient space ({}) to copy node_cert out ({})",
          node_cert_size,
          r.first.node_cert.size());
        return false;
      }
      ::memcpy(node_cert, r.first.node_cert.data(), r.first.node_cert.size());
      *node_cert_len = r.first.node_cert.size();

      if (start_type == StartType::New || start_type == StartType::Recover)
      {
        // When starting a node in start or recover modes, fresh network secrets
        // are created and the associated certificate can be passed to the host
        if (r.first.network_cert.size() > network_cert_size)
        {
          LOG_FAIL_FMT(
            "Insufficient space ({}) to copy network_cert out ({})",
            network_cert_size,
            r.first.network_cert.size());
          return false;
        }
        ::memcpy(
          network_cert,
          r.first.network_cert.data(),
          r.first.network_cert.size());
        *network_cert_len = r.first.network_cert.size();

        if (r.first.network_enc_pubk.size() > network_enc_pubk_size)
        {
          LOG_FAIL_FMT(
            "Insufficient space ({}) to copy network enc pubk out ({})",
            network_enc_pubk_size,
            r.first.network_enc_pubk.size());
          return false;
        }
        ::memcpy(
          network_enc_pubk,
          r.first.network_enc_pubk.data(),
          r.first.network_enc_pubk.size());
        *network_enc_pubk_len = r.first.network_enc_pubk.size();
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
          bp, AdminMessage::stop, [&bp, this](const uint8_t*, size_t) {
            bp.set_finished();
            enclave::ThreadMessaging::thread_messaging.set_finished();
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp, AdminMessage::tick, [this](const uint8_t* data, size_t size) {
            auto [ms_count] =
              ringbuffer::read_message<AdminMessage::tick>(data, size);

            if (ms_count > 0)
            {
              std::chrono::milliseconds elapsed_ms(ms_count);
              logger::config::tick(elapsed_ms);
              node.tick(elapsed_ms);
              timers.tick(elapsed_ms);
              // When recovering, no signature should be emitted while the
              // ledger is being read
              if (!node.is_reading_public_ledger())
              {
                for (auto& r : rpc_map->get_map())
                  r.second->tick(elapsed_ms);
              }
              node.tick_end();
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
              node.node_msg(std::move(body));
            }
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          consensus::ledger_entry,
          [this](const uint8_t* data, size_t size) {
            auto [body] =
              ringbuffer::read_message<consensus::ledger_entry>(data, size);
            if (node.is_reading_public_ledger())
              node.recover_public_ledger_entry(body);
            else if (node.is_reading_private_ledger())
              node.recover_private_ledger_entry(body);
            else
              LOG_FAIL_FMT("Cannot recover ledger entry: Unexpected state");
          });

        DISPATCHER_SET_MESSAGE_HANDLER(
          bp,
          consensus::ledger_no_entry,
          [this](const uint8_t* data, size_t size) {
            ringbuffer::read_message<consensus::ledger_no_entry>(data, size);
            node.recover_ledger_end();
          });

        rpcsessions->register_message_handlers(bp.get_dispatcher());

        if (start_type == StartType::Join)
        {
          node.join({ccf_config});
        }
        else if (start_type == StartType::Recover)
        {
          node.start_ledger_recovery();
        }
        bp.run(circuit->read_from_outside());
        return true;
      }
#ifndef VIRTUAL_ENCLAVE
      catch (const std::exception& e)
      {
        auto w = writer_factory.create_writer_to_outside();
        RINGBUFFER_WRITE_MESSAGE(
          AdminMessage::fatal_error_msg, w, std::string(e.what()));
        return false;
      }
#endif
    }

    struct Msg
    {
      uint64_t tid;
    };

    static void init_thread_cb(std::unique_ptr<enclave::Tmsg<Msg>> msg)
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
        auto msg = std::make_unique<enclave::Tmsg<Msg>>(&init_thread_cb);
        msg->data.tid = thread_ids[std::this_thread::get_id()];
        enclave::ThreadMessaging::thread_messaging.add_task<Msg>(
          msg->data.tid, std::move(msg));

        enclave::ThreadMessaging::thread_messaging.run();
      }
#ifndef VIRTUAL_ENCLAVE
      catch (const std::exception& e)
      {
        auto w = writer_factory.create_writer_to_outside();
        RINGBUFFER_WRITE_MESSAGE(
          AdminMessage::fatal_error_msg, w, std::string(e.what()));
        return false;
      }
#endif
      return true;
    }
  };
}

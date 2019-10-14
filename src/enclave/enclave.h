// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include "appinterface.h"
#include "crypto/hash.h"
#include "ds/logger.h"
#include "ds/oversized.h"
#include "interface.h"
#include "node/entities.h"
#include "node/networkstate.h"
#include "node/nodestate.h"
#include "node/nodetypes.h"
#include "node/notifier.h"
#include "node/rpc/forwarder.h"
#include "node/rpc/memberfrontend.h"
#include "node/rpc/nodefrontend.h"
#include "node/timer.h"
#include "rpcclient.h"
#include "rpcmap.h"
#include "rpcsessions.h"

namespace enclave
{
  class Enclave
  {
  private:
    ringbuffer::Circuit* circuit;
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

  public:
    Enclave(
      EnclaveConfig* enclave_config,
      const CCFConfig::SignatureIntervals& signature_intervals,
      const raft::Config& raft_config) :
      circuit(enclave_config->circuit),
      writer_factory(circuit, enclave_config->writer_config),
      n2n_channels(std::make_shared<ccf::NodeToNode>(writer_factory)),
      notifier(writer_factory),
      rpc_map(std::make_shared<RPCMap>()),
      rpcsessions(std::make_shared<RPCSessions>(writer_factory, rpc_map)),
      node(writer_factory, network, rpcsessions, notifier, timers),
      cmd_forwarder(std::make_shared<ccf::Forwarder<ccf::NodeToNode>>(
        rpcsessions, n2n_channels, rpc_map))
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

      node.initialize(raft_config, n2n_channels, rpc_map, cmd_forwarder);
    }

    bool create_new_node(
      StartType start_type_,
      const CCFConfig& ccf_config_,
      uint8_t* node_cert,
      size_t node_cert_size,
      size_t* node_cert_len,
      uint8_t* quote,
      size_t quote_size,
      size_t* quote_len,
      uint8_t* network_cert,
      size_t network_cert_size,
      size_t* network_cert_len)
    {
      // node_cert_size, quote_size and network_cert_size are ignored here, but
      // we pass them in because it allows us to set EDL an annotation so that
      // quote_len <= quote_size is checked by the EDL-generated wrapper

      start_type = start_type_;
      ccf_config = ccf_config_;

      auto r = node.create({start_type, ccf_config_});
      if (!r.second)
        return false;

      // Copy node, quote and network certs out
      ::memcpy(node_cert, r.first.node_cert.data(), r.first.node_cert.size());
      *node_cert_len = r.first.node_cert.size();

      ::memcpy(quote, r.first.quote.data(), r.first.quote.size());
      *quote_len = r.first.quote.size();

      if (start_type == StartType::New || start_type == StartType::Recover)
      {
        // When starting a node in start or recover modes, fresh network secrets
        // are created and the associated certificate can be passed to the host
        ::memcpy(
          network_cert,
          r.first.network_cert.data(),
          r.first.network_cert.size());
        *network_cert_len = r.first.network_cert.size();
      }

      return true;
    }

    bool run()
    {
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
              node.node_msg(body);
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
  };
}

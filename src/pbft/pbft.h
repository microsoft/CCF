// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/logger.h"
#include "kv/kvtypes.h"
#include "libbyz/libbyz.h"
#include "libbyz/network.h"
#include "libbyz/receive_message_base.h"
#include "node/nodetypes.h"
#include "pbft/pbft_deps.h"

#include <list>
#include <memory>
#include <vector>

namespace pbft
{
  class PbftEnclaveNetwork : public INetwork
  {
  public:
    PbftEnclaveNetwork(
      pbft::NodeId id, std::shared_ptr<ccf::NodeToNode> n2n_channels) :
      n2n_channels(n2n_channels),
      id(id)
    {}

    virtual ~PbftEnclaveNetwork() = default;

    bool Initialize(in_port_t port) override
    {
      return true;
    }

    int Send(Message* msg, IPrincipal& principal) override
    {
      NodeId to = principal.pid();
      PbftHeader hdr = {PbftMsgType::pbft_message, id};

      // TODO: Encrypt msg here
      std::vector<uint8_t> serialized_msg(sizeof(PbftHeader) + msg->size());
      auto data_ = serialized_msg.data();
      auto space = serialized_msg.size();
      serialized::write<PbftHeader>(data_, space, hdr);
      serialized::write(
        data_,
        space,
        reinterpret_cast<const uint8_t*>(msg->contents()),
        msg->size());

      n2n_channels->send_authenticated(
        ccf::NodeMsgType::consensus_msg_pbft, to, serialized_msg);
      return msg->size();
    }

    virtual Message* GetNextMessage() override
    {
      assert("Should not be called");
      return nullptr;
    }

    virtual bool has_messages(long to) override
    {
      return false;
    }

  private:
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    NodeId id;
  };

  template <class ChannelProxy>
  class Pbft : public kv::Replicator
  {
  private:
    NodeId local_id;
    std::shared_ptr<ChannelProxy> channels;
    IMessageReceiveBase* message_receiver_base = nullptr;
    char* mem;
    std::unique_ptr<INetwork> pbft_network;

    struct NodeConfiguration
    {
      NodeId node_id;
      std::string host_name;
      std::string port;
    };

  public:
    Pbft(std::shared_ptr<ChannelProxy> channels_, NodeId id) :
      local_id(id),
      channels(channels_)
    {
      LOG_INFO << "Setting up pbft replica for node with id: " << local_id
               << std::endl;
      // configure replica
      GeneralInfo general_info;
      general_info.num_replicas = 2;
      general_info.num_clients = 0;
      general_info.max_faulty = 0;
      general_info.service_name = "generic";
      general_info.auth_timeout = 1800000;
      general_info.view_timeout = 5000;
      general_info.status_timeout = 100;
      general_info.recovery_timeout = 9999250000;

      // TODO(#pbft): We do not need this in the long run
      std::string privk =
        "0045c65ec31179652c57ae97f50de77e177a939dce74e39d7db51740663afb69";
      std::string pubk_sig =
        "aad14ecb5d7ca8caf5ee68d2762721a3d4fdb09b1ae4a699daf74985193b7d42";
      std::string pubk_enc =
        "893d4101c5b225c2bdc8633bb322c0ef9861e0c899014536e11196808ffc0d17";

      // Adding myself
      PrincipalInfo my_info;
      my_info.id = local_id;
      my_info.port = 0;
      my_info.ip = "256.256.256.256"; // Invalid
      my_info.pubk_sig = pubk_sig;
      my_info.pubk_enc = pubk_enc;
      my_info.host_name = "machineB";
      my_info.is_replica = true;
      LOG_INFO << "PBFT Setup for self with id:" << local_id << std::endl;

      ::NodeInfo node_info = {my_info, privk, general_info};

      int mem_size = 40 * 8192;
      mem = (char*)malloc(mem_size);
      bzero(mem, mem_size);

      auto exec_command = ([](
                             Byz_req* inb,
                             Byz_rep* outb,
                             _Byz_buffer* non_det,
                             int client,
                             bool ro,
                             Seqno n) { return 0; });

      pbft_network = std::make_unique<PbftEnclaveNetwork>(local_id, channels);

      Byz_init_replica(
        node_info,
        mem,
        mem_size,
        exec_command,
        0,
        0,
        pbft_network.get(),
        &message_receiver_base);
    }

    NodeId leader() override
    {
      return 0;
    }

    NodeId id() override
    {
      return local_id;
    }

    bool is_leader() override
    {
      return false;
    }

    Index get_commit_idx() override
    {
      return 0;
    }

    Term get_term() override
    {
      return 0;
    }

    Term get_term(Index idx) override
    {
      return 0;
    }

    void add_configuration(const NodeConfiguration& node_conf)
    {
      // TODO(#pbft): We do not need this in the long run
      std::string privk =
        "0045c65ec31179652c57ae97f50de77e177a939dce74e39d7db51740663afb69";
      std::string pubk_sig =
        "aad14ecb5d7ca8caf5ee68d2762721a3d4fdb09b1ae4a699daf74985193b7d42";
      std::string pubk_enc =
        "893d4101c5b225c2bdc8633bb322c0ef9861e0c899014536e11196808ffc0d17";

      if (node_conf.node_id == local_id)
      {
        return;
      }

      PrincipalInfo info;
      info.id = node_conf.node_id;
      info.port = short(atoi(node_conf.port.c_str()));
      info.ip = "256.256.256.256"; // Invalid
      info.pubk_sig = pubk_sig;
      info.pubk_enc = pubk_enc;
      info.host_name = node_conf.host_name;
      info.is_replica = true;
      LOG_INFO << "PBFT - adding node, id:" << info.id << std::endl;
      Byz_add_principal(info);
      LOG_INFO << "PBFT - added node, id: " << info.id << std::endl;
    }

    bool replicate(
      const std::vector<std::tuple<Index, std::vector<uint8_t>, bool>>& entries)
      override
    {
      return true;
    }

    void recv_message(const uint8_t* data, size_t size)
    {
      switch (serialized::peek<PbftMsgType>(data, size))
      {
        case pbft_message:
          serialized::skip(data, size, sizeof(PbftHeader));
          message_receiver_base->receive_message((char*)((uint64_t)data), size);
          break;
        default:
        {}
      }
    }
  };
}
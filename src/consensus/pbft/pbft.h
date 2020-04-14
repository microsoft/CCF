// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "consensus/ledger_enclave.h"
#include "consensus/pbft/libbyz/append_entries.h"
#include "consensus/pbft/libbyz/big_req_table.h"
#include "consensus/pbft/libbyz/client_proxy.h"
#include "consensus/pbft/libbyz/libbyz.h"
#include "consensus/pbft/libbyz/message_tags.h"
#include "consensus/pbft/libbyz/network.h"
#include "consensus/pbft/libbyz/receive_message_base.h"
#include "consensus/pbft/pbft_config.h"
#include "consensus/pbft/pbft_globals.h"
#include "consensus/pbft/pbft_types.h"
#include "ds/logger.h"
#include "enclave/rpc_map.h"
#include "enclave/rpc_sessions.h"
#include "host/ledger.h"
#include "kv/kv_types.h"
#include "node/nodetypes.h"

#include <list>
#include <memory>
#include <unordered_map>
#include <vector>

namespace pbft
{
  using SeqNo = kv::Consensus::SeqNo;
  using View = kv::Consensus::View;

  struct ViewChangeInfo
  {
    ViewChangeInfo(View view_, SeqNo min_global_commit_) :
      min_global_commit(min_global_commit_),
      view(view_)
    {}

    SeqNo min_global_commit;
    View view;
  };

  struct MarkStableInfo
  {
    pbft::PbftStore* store;
    Index* latest_stable_ae_idx;
  } register_mark_stable_ctx;

  struct GlobalCommitInfo
  {
    pbft::PbftStore* store;
    SeqNo* global_commit_seqno;
    View* last_commit_view;
    std::vector<ViewChangeInfo>* view_change_list;
  } register_global_commit_ctx;

  struct RollbackInfo
  {
    pbft::PbftStore* store;
    consensus::LedgerEnclave* ledger;
  } register_rollback_ctx;

  // maps node to last sent index to that node
  using NodesMap = std::unordered_map<NodeId, Index>;
  static constexpr Index entries_batch_size = 10;

  class PbftEnclaveNetwork : public INetwork
  {
  private:
    void serialize_message(uint8_t*& data, size_t& size, Message* msg)
    {
      serialized::write(
        data,
        size,
        reinterpret_cast<const uint8_t*>(msg->contents()),
        msg->size());
    }

    void send_append_entries(NodeId to, Index start_idx)
    {
      Index end_idx = (latest_stable_ae_index == 0) ?
        0 :
        std::min(start_idx + entries_batch_size, latest_stable_ae_index);

      for (Index i = end_idx; i < latest_stable_ae_index;
           i += entries_batch_size)
      {
        send_append_entries_range(to, start_idx, i);
        start_idx = std::min(i + 1, latest_stable_ae_index);
      }

      if (latest_stable_ae_index == 0 || end_idx <= latest_stable_ae_index)
      {
        send_append_entries_range(to, start_idx, latest_stable_ae_index);
      }
    }

    void send_append_entries_range(NodeId to, Index start_idx, Index end_idx)
    {
      const auto prev_idx = start_idx - 1;

      LOG_INFO_FMT(
        "Send append entries from {} to {}: {} to {}",
        id,
        to,
        start_idx,
        end_idx);

      AppendEntries ae = {pbft_append_entries, id, end_idx, prev_idx};

      auto node = nodes.find(to);
      if (node != nodes.end())
      {
        node->second = end_idx;
      }
      else
      {
        nodes[to] = end_idx;
      }

      auto tmsg = std::make_unique<enclave::Tmsg<SendAuthenticatedAEMsg>>(
        &send_authenticated_ae_msg_cb,
        ae,
        this,
        ccf::NodeMsgType::consensus_msg,
        to);

      if (enclave::ThreadMessaging::thread_count > 1)
      {
        uint16_t tid = enclave::ThreadMessaging::get_execution_thread(to);
        enclave::ThreadMessaging::thread_messaging
          .add_task<SendAuthenticatedAEMsg>(tid, std::move(tmsg));
      }
      else
      {
        tmsg->cb(std::move(tmsg));
      }
    }

    bool should_encrypt(int tag)
    {
#ifdef USE_NULL_ENCRYPTOR
      return false;
#else
      return tag == Request_tag || tag == Reply_tag;
#endif
    }

    std::vector<uint8_t> serialized_msg;

  public:
    PbftEnclaveNetwork(
      NodeId id,
      std::shared_ptr<ccf::NodeToNode> n2n_channels,
      NodesMap& nodes_,
      Index& latest_stable_ae_index_) :
      n2n_channels(n2n_channels),
      id(id),
      nodes(nodes_),
      latest_stable_ae_index(latest_stable_ae_index_)
    {}

    virtual ~PbftEnclaveNetwork() = default;

    bool Initialize(in_port_t port) override
    {
      return true;
    }

    void set_receiver(IMessageReceiveBase* receiver)
    {
      message_receiver_base = receiver;
    }

    struct SendAuthenticatedAEMsg
    {
      SendAuthenticatedAEMsg(
        AppendEntries ae_,
        PbftEnclaveNetwork* self_,
        ccf::NodeMsgType type_,
        pbft::NodeId to_) :
        ae(std::move(ae_)),
        self(self_),
        type(type_),
        to(to_)
      {}

      AppendEntries ae;
      ccf::NodeMsgType type;
      pbft::NodeId to;
      PbftEnclaveNetwork* self;
    };

    static void send_authenticated_ae_msg_cb(
      std::unique_ptr<enclave::Tmsg<SendAuthenticatedAEMsg>> msg)
    {
      msg->data.self->n2n_channels->send_authenticated(
        msg->data.type, msg->data.to, msg->data.ae);
    }

    struct SendAuthenticatedMsg
    {
      SendAuthenticatedMsg(
        bool should_encrypt_,
        std::vector<uint8_t> data_,
        PbftEnclaveNetwork* self_,
        ccf::NodeMsgType type_,
        pbft::NodeId to_) :
        should_encrypt(should_encrypt_),
        data(std::move(data_)),
        self(self_),
        type(type_),
        to(to_)
      {}

      bool should_encrypt;
      std::vector<uint8_t> data;
      ccf::NodeMsgType type;
      pbft::NodeId to;
      PbftEnclaveNetwork* self;
    };

    static void send_authenticated_msg_cb(
      std::unique_ptr<enclave::Tmsg<SendAuthenticatedMsg>> msg)
    {
      if (msg->data.should_encrypt)
      {
        PbftHeader hdr = {PbftMsgType::encrypted_pbft_message,
                          msg->data.self->id};
        msg->data.self->n2n_channels->send_encrypted(
          ccf::NodeMsgType::consensus_msg, msg->data.to, msg->data.data, hdr);
      }
      else
      {
        msg->data.self->n2n_channels->send_authenticated(
          msg->data.type, msg->data.to, msg->data.data);
      }
    }

    int Send(Message* msg, IPrincipal& principal) override
    {
      NodeId to = principal.pid();
      if (to == id)
      {
        // If a replica sends a message to itself (e.g. if f == 0), handle
        // the message straight away without writing it to the ringbuffer
        message_receiver_base->receive_message(
          (const uint8_t*)(msg->contents()), msg->size());
        return msg->size();
      }

      if (msg->tag() == Append_entries_tag)
      {
        auto node = nodes.find(to);

        Index match_idx = 0;
        if (node != nodes.end())
        {
          match_idx = node->second;
        }

        if (match_idx < latest_stable_ae_index)
        {
          send_append_entries(to, match_idx + 1);
        }
        return msg->size();
      }

      bool encrypt = should_encrypt(msg->tag());
      if (encrypt)
      {
        size_t space = msg->size();
        serialized_msg.resize(space);
        auto data_ = serialized_msg.data();
        serialize_message(data_, space, msg);
      }
      else
      {
        PbftHeader hdr = {PbftMsgType::pbft_message, id};
        auto space = (sizeof(PbftHeader) + msg->size());
        serialized_msg.resize(space);
        auto data_ = serialized_msg.data();
        serialized::write<PbftHeader>(data_, space, hdr);
        serialize_message(data_, space, msg);
      }

      auto tmsg = std::make_unique<enclave::Tmsg<SendAuthenticatedMsg>>(
        &send_authenticated_msg_cb,
        encrypt,
        std::move(serialized_msg),
        this,
        ccf::NodeMsgType::consensus_msg,
        to);

      if (enclave::ThreadMessaging::thread_count > 1)
      {
        uint16_t tid = enclave::ThreadMessaging::get_execution_thread(
          ++execution_thread_counter);
        enclave::ThreadMessaging::thread_messaging
          .add_task<SendAuthenticatedMsg>(tid, std::move(tmsg));
      }
      else
      {
        tmsg->cb(std::move(tmsg));
      }

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
    uint32_t execution_thread_counter = 0;
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    IMessageReceiveBase* message_receiver_base = nullptr;
    NodeId id;
    NodesMap& nodes;
    Index& latest_stable_ae_index;
  };

  template <class LedgerProxy, class ChannelProxy>
  class Pbft : public kv::Consensus
  {
  private:
    NodesMap nodes;

    std::shared_ptr<ChannelProxy> channels;
    IMessageReceiveBase* message_receiver_base = nullptr;
    char* mem;
    std::unique_ptr<PbftEnclaveNetwork> pbft_network;
    std::unique_ptr<AbstractPbftConfig> pbft_config;
    std::unique_ptr<ClientProxy<kv::TxHistory::RequestID, void>> client_proxy;
    std::shared_ptr<enclave::RPCSessions> rpcsessions;
    SeqNo global_commit_seqno;
    View last_commit_view;
    std::unique_ptr<pbft::PbftStore> store;
    std::unique_ptr<consensus::LedgerEnclave> ledger;
    Index latest_stable_ae_index = 0;

    // When this is set, only public domain is deserialised when receving append
    // entries
    bool public_only = false;
    std::vector<ViewChangeInfo> view_change_list;

  public:
    Pbft(
      std::unique_ptr<pbft::PbftStore> store_,
      std::shared_ptr<ChannelProxy> channels_,
      NodeId id,
      size_t sig_max_tx,
      std::unique_ptr<consensus::LedgerEnclave> ledger_,
      std::shared_ptr<enclave::RPCMap> rpc_map,
      std::shared_ptr<enclave::RPCSessions> rpcsessions_,
      pbft::RequestsMap& pbft_requests_map,
      pbft::PrePreparesMap& pbft_pre_prepares_map,
      ccf::Signatures& signatures,
      const std::string& privk_pem,
      const std::vector<uint8_t>& cert,
      const consensus::Config& consensus_config) :
      Consensus(id),
      channels(channels_),
      rpcsessions(rpcsessions_),
      ledger(std::move(ledger_)),
      global_commit_seqno(1),
      last_commit_view(0),
      store(std::move(store_)),
      view_change_list(1, ViewChangeInfo(0, 0))
    {
      // configure replica
      GeneralInfo general_info;
      general_info.num_replicas = 1;
      general_info.num_clients = 1;
      general_info.max_faulty = 0;
      general_info.service_name = "generic";
      general_info.auth_timeout = 1800000;
      general_info.view_timeout = consensus_config.pbft_view_change_timeout;
      general_info.status_timeout = consensus_config.pbft_status_interval;
      general_info.recovery_timeout = 9999250000;
      general_info.max_requests_between_signatures =
        sig_max_tx / Max_requests_in_batch;
      general_info.support_threading = true;

      // Adding myself
      PrincipalInfo my_info;
      my_info.id = local_id;
      my_info.port = 0;
      my_info.ip = "256.256.256.256"; // Invalid
      my_info.cert = cert;
      my_info.host_name = "machineB";
      my_info.is_replica = true;

      ::NodeInfo node_info = {my_info, privk_pem, general_info};

      int mem_size = 64;
      mem = (char*)malloc(mem_size);
      bzero(mem, mem_size);

      pbft_network = std::make_unique<PbftEnclaveNetwork>(
        local_id, channels, nodes, latest_stable_ae_index);
      pbft_config = std::make_unique<PbftConfigCcf>(rpc_map);

      auto used_bytes = Byz_init_replica(
        node_info,
        mem,
        mem_size,
        pbft_config->get_exec_command(),
        pbft_network.get(),
        pbft_requests_map,
        pbft_pre_prepares_map,
        signatures,
        *store,
        &message_receiver_base);
      LOG_INFO_FMT("PBFT setup for local_id: {}", local_id);

      pbft_config->set_service_mem(mem + used_bytes);
      pbft_config->set_receiver(message_receiver_base);
      pbft_network->set_receiver(message_receiver_base);

      Byz_start_replica();

      LOG_INFO_FMT("PBFT setting up client proxy");
      client_proxy =
        std::make_unique<ClientProxy<kv::TxHistory::RequestID, void>>(
          *message_receiver_base, 5000, 10000);

      auto reply_handler_cb = [](Reply* m, void* ctx) {
        auto cp =
          static_cast<ClientProxy<kv::TxHistory::RequestID, void>*>(ctx);
        cp->recv_reply(m);
      };
      message_receiver_base->register_reply_handler(
        reply_handler_cb, client_proxy.get());

      auto mark_stable_cb = [](MarkStableInfo* ms_info) {
        *ms_info->latest_stable_ae_idx = ms_info->store->current_version();
        LOG_TRACE_FMT(
          "latest_stable_ae_index is set to {}",
          *ms_info->latest_stable_ae_idx);
      };

      register_mark_stable_ctx.store = store.get();
      register_mark_stable_ctx.latest_stable_ae_idx = &latest_stable_ae_index;

      message_receiver_base->register_mark_stable(
        mark_stable_cb, &register_mark_stable_ctx);

      auto global_commit_cb = [](
                                kv::Version version,
                                ::View view,
                                GlobalCommitInfo* gb_info) {
        if (version == kv::NoVersion || version < *gb_info->global_commit_seqno)
        {
          return;
        }
        *gb_info->global_commit_seqno = version;

        if (*gb_info->last_commit_view < view)
        {
          gb_info->view_change_list->emplace_back(view, version);
        }
        gb_info->store->compact(version);
      };

      register_global_commit_ctx.store = store.get();
      register_global_commit_ctx.global_commit_seqno = &global_commit_seqno;
      register_global_commit_ctx.last_commit_view = &last_commit_view;
      register_global_commit_ctx.view_change_list = &view_change_list;

      message_receiver_base->register_global_commit(
        global_commit_cb, &register_global_commit_ctx);

      auto rollback_cb = [](kv::Version version, RollbackInfo* rollback_info) {
        LOG_TRACE_FMT(
          "Rolling back to version {} and truncating ledger", version);
        rollback_info->store->rollback(version);
        rollback_info->ledger->truncate(version);
      };

      register_rollback_ctx.store = store.get();
      register_rollback_ctx.ledger = ledger.get();

      message_receiver_base->register_rollback_cb(
        rollback_cb, &register_rollback_ctx);
    }

    bool on_request(const kv::TxHistory::RequestCallbackArgs& args) override
    {
      pbft::Request request = {
        args.caller_id, args.caller_cert, args.request, {}};
      auto serialized_req = request.serialise();

      auto rep_cb = [&](
                      void* owner,
                      kv::TxHistory::RequestID caller_rid,
                      int status,
                      std::vector<uint8_t>& data) {
        LOG_DEBUG_FMT("PBFT reply callback for {}", caller_rid);

        return rpcsessions->reply_async(std::get<1>(caller_rid), data);
      };

      LOG_DEBUG_FMT("PBFT sending request {}", args.rid);
      return client_proxy->send_request(
        args.rid,
        serialized_req.data(),
        serialized_req.size(),
        rep_cb,
        client_proxy.get());
    }

    View get_view() override
    {
      return message_receiver_base->view() + 2;
    }

    View get_view(SeqNo seqno) override
    {
      for (auto rit = view_change_list.rbegin(); rit != view_change_list.rend();
           ++rit)
      {
        ViewChangeInfo& info = *rit;
        if (info.min_global_commit <= seqno)
        {
          return info.view + 2;
        }
      }
      throw std::logic_error("should never be here");
    }

    SeqNo get_commit_seqno() override
    {
      return global_commit_seqno;
    }

    kv::NodeId primary() override
    {
      return message_receiver_base->primary();
    }

    bool is_primary() override
    {
      return message_receiver_base->is_primary();
    }

    bool is_backup() override
    {
      return !message_receiver_base->is_primary();
    }

    void add_configuration(
      SeqNo seqno,
      std::unordered_set<kv::NodeId> config,
      const NodeConf& node_conf) override
    {
      if (node_conf.node_id == local_id)
      {
        return;
      }

      PrincipalInfo info;
      info.id = node_conf.node_id;
      info.port = short(atoi(node_conf.port.c_str()));
      info.ip = "256.256.256.256"; // Invalid
      info.cert = node_conf.cert;
      info.host_name = node_conf.host_name;
      info.is_replica = true;
      Byz_add_principal(info);
      LOG_INFO_FMT("PBFT added node, id: {}", info.id);

      nodes[node_conf.node_id] = 0;
    }

    void periodic(std::chrono::milliseconds elapsed) override
    {
      client_proxy->periodic(elapsed);
      ITimer::handle_timeouts(elapsed);
    }

    void periodic_end() override
    {
      client_proxy->reset_statistics();
    }

    Statistics get_statistics() override
    {
      return client_proxy->get_statistics();
    }

    template <typename T>
    size_t write_to_ledger(const T& data)
    {
      ledger->put_entry(data->data(), data->size());
      return data->size();
    }

    template <>
    size_t write_to_ledger<std::vector<uint8_t>>(
      const std::vector<uint8_t>& data)
    {
      ledger->put_entry(data);
      return data.size();
    }

    bool replicate(const kv::BatchVector& entries) override
    {
      for (auto& [index, data, globally_committable] : entries)
      {
        write_to_ledger(data);
      }
      return true;
    }

    struct RecvAuthenticatedMsg
    {
      RecvAuthenticatedMsg(
        bool should_decrypt_,
        OArray&& d_,
        Pbft<LedgerProxy, ChannelProxy>* self_) :
        should_decrypt(should_decrypt_),
        d(std::move(d_)),
        self(self_),
        result(false)
      {}

      bool should_decrypt;
      OArray d;
      Pbft<LedgerProxy, ChannelProxy>* self;
      bool result;
    };

    static void recv_authenticated_msg_cb(
      std::unique_ptr<enclave::Tmsg<RecvAuthenticatedMsg>> msg)
    {
      if (msg->data.should_decrypt)
      {
        std::pair<PbftHeader, std::vector<uint8_t>> r;
        try
        {
          r = msg->data.self->channels->template recv_encrypted<PbftHeader>(
            msg->data.d.data(), msg->data.d.size());
          OArray decrypted(std::move(r.second));
          msg->data.d = std::move(decrypted);
        }
        catch (const std::logic_error& err)
        {
          LOG_FAIL_FMT("Invalid encrypted pbft message: {}", err.what());
          return;
        }
      }
      else
      {
        try
        {
          auto r = msg->data.self->channels
                     ->template recv_authenticated_with_load<PbftHeader>(
                       msg->data.d.data(), msg->data.d.size());
          msg->data.d.data() = r.p;
          msg->data.d.size() = r.n;
        }
        catch (const std::logic_error& err)
        {
          LOG_FAIL_FMT("Invalid pbft message: {}", err.what());
          return;
        }
      }

      msg->data.result = true;
      enclave::ThreadMessaging::ChangeTmsgCallback(
        msg, &recv_authenticated_msg_process_cb);
      if (enclave::ThreadMessaging::thread_count > 1)
      {
        enclave::ThreadMessaging::thread_messaging
          .add_task<RecvAuthenticatedMsg>(
            enclave::ThreadMessaging::main_thread, std::move(msg));
      }
      else
      {
        msg->cb(std::move(msg));
      }
    }

    static void recv_authenticated_msg_process_cb(
      std::unique_ptr<enclave::Tmsg<RecvAuthenticatedMsg>> msg)
    {
      assert(msg->data.result);
      msg->data.self->message_receiver_base->receive_message(
        msg->data.d.data(), msg->data.d.size());
    }

    void recv_message(OArray&& d) override
    {
      const uint8_t* data = d.data();
      size_t size = d.size();
      PbftHeader hdr = serialized::peek<PbftHeader>(data, size);
      switch (hdr.msg)
      {
        case encrypted_pbft_message:
        case pbft_message:
        {
          bool should_decrypt = (hdr.msg == encrypted_pbft_message);
          auto tmsg = std::make_unique<enclave::Tmsg<RecvAuthenticatedMsg>>(
            &recv_authenticated_msg_cb, should_decrypt, std::move(d), this);

          ccf::RecvNonce recv_nonce(0);
          if (should_decrypt)
          {
            recv_nonce =
              channels->template get_encrypted_recv_nonce<PbftHeader>(
                tmsg->data.d.data(), tmsg->data.d.size());
          }
          else
          {
            recv_nonce = channels->template get_recv_nonce<PbftHeader>(
              tmsg->data.d.data(), tmsg->data.d.size());
          }

          if (enclave::ThreadMessaging::thread_count > 1)
          {
            enclave::ThreadMessaging::thread_messaging
              .add_task<RecvAuthenticatedMsg>(
                recv_nonce.tid % enclave::ThreadMessaging::thread_count,
                std::move(tmsg));
          }
          else
          {
            tmsg->cb(std::move(tmsg));
          }

          break;
        }
        case pbft_append_entries:
        {
          if (message_receiver_base->IsExecutionPending())
          {
            LOG_FAIL << "Pending Execution, skipping append entries request"
                     << std::endl;
            return;
          }

          AppendEntries r;

          auto append_entries_index = store->current_version();

          try
          {
            r =
              channels->template recv_authenticated<AppendEntries>(data, size);
          }
          catch (const std::logic_error& err)
          {
            LOG_FAIL_FMT(err.what());
            return;
          }

          LOG_TRACE_FMT(
            "Append entries message from {}, my ae index is {}",
            r.from_node,
            append_entries_index);

          auto node = nodes.find(r.from_node);
          if (node != nodes.end())
          {
            node->second = r.idx;
          }
          else
          {
            nodes[r.from_node] = r.idx;
          }

          if (r.idx <= append_entries_index)
          {
            LOG_TRACE_FMT(
              "Skipping append entries msg for index {} as we are at index {}",
              r.idx,
              append_entries_index);
            break;
          }

          for (Index i = r.prev_idx + 1; i <= r.idx; i++)
          {
            append_entries_index = store->current_version();
            LOG_TRACE_FMT("Recording entry for index {}", i);

            if (i <= append_entries_index)
            {
              // If the current entry has already been deserialised, skip the
              // payload for that entry
              LOG_INFO_FMT(
                "Skipping index {} as we are at index {}",
                i,
                append_entries_index);
              ledger->skip_entry(data, size);
              continue;
            }
            LOG_TRACE_FMT("Applying append entry for index {}", i);

            auto ret = ledger->get_entry(data, size);

            if (!ret.second)
            {
              // NB: This will currently never be triggered.
              // This should only fail if there is malformed data. Truncate
              // the log and reply false.
              LOG_FAIL_FMT(
                "Recv append entries to {} from {} but the data is malformed",
                local_id,
                r.from_node);
              ledger->truncate(r.prev_idx);
              return;
            }

            ccf::Store::Tx tx;
            auto deserialise_success =
              store->deserialise_views(ret.first, public_only, nullptr, &tx);

            switch (deserialise_success)
            {
              case kv::DeserialiseSuccess::FAILED:
              {
                LOG_FAIL_FMT("Replica failed to apply log entry {}", i);
                break;
              }
              case kv::DeserialiseSuccess::PASS:
              {
                message_receiver_base->playback_request(tx);
                break;
              }
              case kv::DeserialiseSuccess::PASS_PRE_PREPARE:
              {
                message_receiver_base->playback_pre_prepare(tx);
                break;
              }
              default:
                throw std::logic_error("Unknown DeserialiseSuccess value");
            }
          }
          break;
        }
      }
    }

    void set_f(ccf::NodeId f) override
    {
      message_receiver_base->set_f(f);
    }

    void emit_signature() override
    {
      kv::Version version = store->current_version();
      if (message_receiver_base != nullptr)
      {
        message_receiver_base->emit_signature_on_next_pp(version);
      }
    }

    ConsensusType type() override
    {
      return ConsensusType::PBFT;
    }
  };
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "impl/message.h"
#include "ds/ccf_assert.h"
#include "impl/replica.h"
#include "ds/serialized.h"
#include "node/nodetypes.h"
#include "ds/ccf_assert.h"
#include "ds/thread_messaging.h"
#include "node/node_to_node.h"
#include "aft_types.h"

namespace aft {

  class INetwork
  {
  public:
    using recv_message_cb = std::function<void(OArray oa, kv::NodeId id)>;
    using recv_message_ae_cb = std::function<void(OArray oa, AppendEntries ae, kv::NodeId id)>;

    INetwork() = default;
    virtual ~INetwork() = default;
    virtual int Send(IMessage& msg, Replica& replica) = 0;
    virtual int Send(IMessage& msg, kv::NodeId to) = 0;
    virtual int Send(AppendEntries ae, kv::NodeId to) = 0;
    virtual void recv_message(OArray d) = 0;
  };

  class EnclaveNetwork : public INetwork
  {
  public:
    EnclaveNetwork(
      kv::NodeId id,
      std::shared_ptr<ccf::NodeToNode> n2n_channels,
      recv_message_cb cb_,
      recv_message_ae_cb cb_ae_) :
      n2n_channels(n2n_channels), id(id), cb(cb_), cb_ae(cb_ae_)
    {}

    virtual ~EnclaveNetwork() = default;

    struct SendAuthenticatedMsg
    {
      SendAuthenticatedMsg(
        bool should_encrypt_,
        std::vector<uint8_t> data_,
        EnclaveNetwork* self_,
        ccf::NodeMsgType type_,
        kv::NodeId to_) :
        should_encrypt(should_encrypt_),
        data(std::move(data_)),
        self(self_),
        type(type_),
        to(to_)
      {}

      bool should_encrypt;
      std::vector<uint8_t> data;
      EnclaveNetwork* self;
      ccf::NodeMsgType type;
      kv::NodeId to;
    };

    static void send_authenticated_msg_cb(
      std::unique_ptr<threading::Tmsg<SendAuthenticatedMsg>> msg)
    {
      if (msg->data.should_encrypt)
      {
        AftHeader hdr = {AftMsgType::encrypted_aft_message,
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

    int Send(IMessage& msg, Replica& replica) override
    {
      return Send(msg, replica.get_id());
    }

    virtual int Send(IMessage& msg, kv::NodeId to) override
    {
      CCF_ASSERT(to != id, "cannot send message to self");
      LOG_INFO_FMT("Sending to {}", to);

      std::vector<uint8_t> serialized_msg;

      bool encrypt = msg.should_encrypt();
      if (encrypt)
      {
        size_t space = msg.size();
        serialized_msg.resize(space);
        auto data_ = serialized_msg.data();
        msg.serialize_message(data_, space);
      }
      else
      {
        AftHeader hdr = {AftMsgType::aft_message, id};
        auto space = (sizeof(AftHeader) + msg.size());
        serialized_msg.resize(space);
        auto data_ = serialized_msg.data();
        serialized::write<AftHeader>(data_, space, hdr);
        msg.serialize_message(data_, space);
      }

      auto tmsg = std::make_unique<threading::Tmsg<SendAuthenticatedMsg>>(
        &send_authenticated_msg_cb,
        encrypt,
        std::move(serialized_msg),
        this,
        ccf::NodeMsgType::consensus_msg,
        to);

      if (threading::ThreadMessaging::thread_count > 1)
      {
        uint16_t tid = threading::ThreadMessaging::get_execution_thread(
          ++execution_thread_counter);
        threading::ThreadMessaging::thread_messaging
          .add_task<SendAuthenticatedMsg>(tid, std::move(tmsg));
      }
      else
      {
        tmsg->cb(std::move(tmsg));
      }

      return msg.size();
    }

    struct RecvAuthenticatedMsg
    {
      RecvAuthenticatedMsg(
        bool should_decrypt_,
        OArray d_,
        EnclaveNetwork* self_,
        recv_message_cb cb_) :
        should_decrypt(should_decrypt_),
        d(std::move(d_)),
        self(self_),
        cb(cb_),
        result(false)
      {}

      bool should_decrypt;
      OArray d;
      EnclaveNetwork* self;
      recv_message_cb cb;
      bool result;
      AftHeader hdr;
    };

    void recv_message(OArray d) override
    {
      const uint8_t* data = d.data();
      size_t size = d.size();
      AftHeader hdr = serialized::peek<AftHeader>(data, size);
      switch (hdr.msg)
      {
        case encrypted_aft_message:
        case aft_message:
        {
          bool should_decrypt = (hdr.msg == encrypted_aft_message);
          auto tmsg = std::make_unique<threading::Tmsg<RecvAuthenticatedMsg>>(
            &recv_authenticated_msg_cb, should_decrypt, std::move(d), this, cb);

          ccf::RecvNonce recv_nonce(0);
          if (should_decrypt)
          {
            recv_nonce =
              n2n_channels->template get_encrypted_recv_nonce<AftHeader>(
                tmsg->data.d.data(), tmsg->data.d.size());
          }
          else
          {
            recv_nonce = n2n_channels->template get_recv_nonce<AftHeader>(
              tmsg->data.d.data(), tmsg->data.d.size());
          }

          if (threading::ThreadMessaging::thread_count > 1)
          {
            threading::ThreadMessaging::thread_messaging
              .add_task<RecvAuthenticatedMsg>(
                recv_nonce.tid % threading::ThreadMessaging::thread_count,
                std::move(tmsg));
          }
          else
          {
            tmsg->cb(std::move(tmsg));
          }

          break;
        }
        case aft_append_entries:

          AppendEntries ae;
          try
          {
            // TODO: this should be returned on the correct thread 
            ae =
              n2n_channels->template recv_authenticated<AppendEntries>(d.data(), d.size());
          }
          catch (const std::logic_error& err)
          {
            CCF_ASSERT_FMT_FAIL("failed to authenticate append entries, err - {}", err.what());
          }

          cb_ae(std::move(d), ae, hdr.from_node);

          break;
        default:
        {
          CCF_ASSERT_FMT_FAIL("Unknown message type {}", hdr.msg);
        }
      }
    }

    static void recv_authenticated_msg_cb(
      std::unique_ptr<threading::Tmsg<RecvAuthenticatedMsg>> msg)
    {
      if (msg->data.should_decrypt)
      {
        std::pair<AftHeader, std::vector<uint8_t>> r;
        try
        {
          r = msg->data.self->n2n_channels->template recv_encrypted<AftHeader>(
            msg->data.d.data(), msg->data.d.size());
          OArray decrypted(std::move(r.second));
          msg->data.d = std::move(decrypted);
          msg->data.hdr = r.first;
        }
        catch (const std::logic_error& err)
        {
          LOG_FAIL_FMT("Invalid encrypted pbft message");
          LOG_DEBUG_FMT("Invalid encrypted pbft message: {}", err.what());
          return;
        }
      }
      else
      {
        try
        {
          msg->data.hdr = msg->data.self->n2n_channels
            ->template recv_authenticated_with_load<AftHeader>(
              msg->data.d.data(), msg->data.d.size());
        }
        catch (const std::logic_error& err)
        {
          LOG_FAIL_FMT("Invalid pbft message");
          LOG_DEBUG_FMT("Invalid pbft message: {}", err.what());
          return;
        }
      }

      msg->data.result = true;
      threading::ThreadMessaging::ChangeTmsgCallback(
        msg, &recv_authenticated_msg_process_cb);
      if (threading::ThreadMessaging::thread_count > 1)
      {
        threading::ThreadMessaging::thread_messaging
          .add_task<RecvAuthenticatedMsg>(
            threading::ThreadMessaging::main_thread, std::move(msg));
      }
      else
      {
        msg->cb(std::move(msg));
      }
    }

    static void recv_authenticated_msg_process_cb(
      std::unique_ptr<threading::Tmsg<RecvAuthenticatedMsg>> msg)
    {
      msg->data.cb(std::move(msg->data.d), msg->data.hdr.from_node);
    }

    struct SendAuthenticatedAEMsg
    {
      SendAuthenticatedAEMsg(
        AppendEntries ae_,
        ccf::NodeMsgType type_,
        kv::NodeId to_,
        EnclaveNetwork* self_) :
        ae(std::move(ae_)), type(type_), to(to_), self(self_)
      {}

      AppendEntries ae;
      ccf::NodeMsgType type;
      kv::NodeId to;
      EnclaveNetwork* self;
    };

    int Send(AppendEntries ae, kv::NodeId to) override
    {
      auto tmsg = std::make_unique<threading::Tmsg<SendAuthenticatedAEMsg>>(
        &send_authenticated_ae_msg_cb,
        ae,
        ccf::NodeMsgType::consensus_msg,
        to,
        this);

      if (threading::ThreadMessaging::thread_count > 1)
      {
        uint16_t tid = threading::ThreadMessaging::get_execution_thread(to);
        threading::ThreadMessaging::thread_messaging
          .add_task<SendAuthenticatedAEMsg>(tid, std::move(tmsg));
      }
      else
      {
        tmsg->cb(std::move(tmsg));
      }

      return sizeof(ae);
    }

    static void send_authenticated_ae_msg_cb(
      std::unique_ptr<threading::Tmsg<SendAuthenticatedAEMsg>> msg)
    {
      msg->data.self->n2n_channels->send_authenticated(
        msg->data.type, msg->data.to, msg->data.ae);
    }

    kv::NodeId get_my_node_id() const
    {
      return id;
    }

  private:
    uint32_t execution_thread_counter = 0;
    std::shared_ptr<ccf::NodeToNode> n2n_channels;
    kv::NodeId id;
    recv_message_cb cb;
    recv_message_ae_cb cb_ae;
  };
}
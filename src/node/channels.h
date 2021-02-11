// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "ds/spin_lock.h"
#include "entities.h"
#include "node_types.h"
#include "tls/key_exchange.h"
#include "tls/key_pair.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

namespace ccf
{
  using SeqNo = uint64_t;
  using GcmHdr = crypto::GcmHeader<sizeof(SeqNo)>;

  struct RecvNonce
  {
    uint8_t tid;
    uint64_t nonce : (sizeof(uint64_t) - sizeof(uint8_t)) * CHAR_BIT;

    RecvNonce(uint64_t nonce_, uint8_t tid_) : tid(tid_), nonce(nonce_) {}
    RecvNonce(const uint64_t header)
    {
      *this = *reinterpret_cast<const RecvNonce*>(&header);
    }

    uint64_t get_val() const
    {
      return *reinterpret_cast<const uint64_t*>(this);
    }
  };
  static_assert(
    sizeof(RecvNonce) == sizeof(SeqNo), "RecvNonce is the wrong size");

  static inline RecvNonce get_nonce(const GcmHdr& header)
  {
    return RecvNonce(header.get_iv_int());
  }

  enum ChannelStatus
  {
    INITIATED = 0,
    ESTABLISHED
  };

  class Channel
  {
  private:
    struct OutgoingMsg
    {
      NodeMsgType type;
      std::vector<uint8_t> raw_plain; // To be integrity-protected
      std::vector<uint8_t> raw_cipher; // To be encrypted

      OutgoingMsg(
        NodeMsgType msg_type, CBuffer raw_plain_, CBuffer raw_cipher_) :
        type(msg_type),
        raw_plain(raw_plain_),
        raw_cipher(raw_cipher_)
      {}
    };

    NodeId self;
    tls::KeyPairPtr network_kp;

    // Notifies the host to create a new outgoing connection
    ringbuffer::WriterPtr to_host;
    NodeId peer_id;
    std::string peer_hostname;
    std::string peer_service;
    bool outgoing;

    // Used for key exchange
    tls::KeyExchangeContext ctx;
    ChannelStatus status = INITIATED;

    // Used for AES GCM authentication/encryption
    std::unique_ptr<crypto::KeyAesGcm> key;

    // Incremented for each tagged/encrypted message
    std::atomic<SeqNo> send_nonce{1};

    // Used to buffer at most one message sent on the channel before it is
    // established
    std::optional<OutgoingMsg> outgoing_msg;

    // Used to prevent replayed messages.
    // Set to the latest successfully received nonce.
    struct ChannelSeqno
    {
      SeqNo main_thread_seqno;
      SeqNo tid_seqno;
    };
    std::array<ChannelSeqno, threading::ThreadMessaging::max_num_threads>
      local_recv_nonce = {{}};

    bool verify_or_decrypt(
      const GcmHdr& header,
      CBuffer aad,
      CBuffer cipher = nullb,
      Buffer plain = {})
    {
      if (status != ESTABLISHED)
      {
        throw std::logic_error("Channel is not established for verifying");
      }

      RecvNonce recv_nonce(header.get_iv_int());
      auto tid = recv_nonce.tid;

      uint16_t current_tid = threading::get_current_thread_id();
      assert(
        current_tid == threading::ThreadMessaging::main_thread ||
        current_tid % threading::ThreadMessaging::thread_count == tid);

      SeqNo* local_nonce;
      if (current_tid == threading::ThreadMessaging::main_thread)
      {
        local_nonce = &local_recv_nonce[tid].main_thread_seqno;
      }
      else
      {
        local_nonce = &local_recv_nonce[tid].tid_seqno;
      }

      if (recv_nonce.nonce <= *local_nonce)
      {
        // If the nonce received has already been processed, return
        LOG_FAIL_FMT(
          "Invalid nonce, possible replay attack, from:{} received:{}, "
          "last_seen:{}, recv_nonce.tid:{}",
          peer_id,
          reinterpret_cast<uint64_t>(recv_nonce.nonce),
          *local_nonce,
          recv_nonce.tid);
        return false;
      }

      auto ret =
        key->decrypt(header.get_iv(), header.tag, cipher, aad, plain.p);
      if (ret)
      {
        // Set local recv nonce to received nonce only if verification is
        // successful
        *local_nonce = recv_nonce.nonce;
      }

      return ret;
    }

    void try_establish_channel()
    {
      ChannelHeader msg = {ChannelMsg::key_exchange, self};
      to_host->write(
        node_outbound,
        peer_id,
        NodeMsgType::channel_msg,
        msg,
        get_signed_public());

      LOG_DEBUG_FMT("node channel with {} initiated", peer_id);
    }

  public:
    Channel(
      ringbuffer::AbstractWriterFactory& writer_factory,
      tls::KeyPairPtr network_kp_,
      NodeId self_,
      NodeId peer_id_,
      const std::string& peer_hostname_,
      const std::string& peer_service_) :
      self(self_),
      network_kp(network_kp_),
      to_host(writer_factory.create_writer_to_outside()),
      peer_id(peer_id_),
      peer_hostname(peer_hostname_),
      peer_service(peer_service_),
      outgoing(true)
    {
      RINGBUFFER_WRITE_MESSAGE(
        ccf::add_node, to_host, peer_id, peer_hostname, peer_service);
    }

    Channel(
      ringbuffer::AbstractWriterFactory& writer_factory,
      tls::KeyPairPtr network_kp_,
      NodeId self_,
      NodeId peer_id_) :
      self(self_),
      network_kp(network_kp_),
      to_host(writer_factory.create_writer_to_outside()),
      peer_id(peer_id_),
      outgoing(false)
    {}

    ~Channel()
    {
      if (outgoing)
      {
        RINGBUFFER_WRITE_MESSAGE(ccf::remove_node, to_host, peer_id);
      }
    }

    void set_status(ChannelStatus status_)
    {
      status = status_;
    }

    ChannelStatus get_status()
    {
      return status;
    }

    bool is_outgoing() const
    {
      return outgoing;
    }

    void set_outgoing(
      const std::string& peer_hostname_, const std::string& peer_service_)
    {
      peer_hostname = peer_hostname_;
      peer_service = peer_service_;

      if (!outgoing)
      {
        RINGBUFFER_WRITE_MESSAGE(
          ccf::add_node, to_host, peer_id, peer_hostname, peer_service);
      }
      outgoing = true;
    }

    void reset_outgoing()
    {
      if (outgoing)
      {
        RINGBUFFER_WRITE_MESSAGE(ccf::remove_node, to_host, peer_id);
      }
      outgoing = false;
    }

    std::vector<uint8_t> get_signed_public()
    {
      const auto own_public = ctx.get_own_public();
      auto signature = network_kp->sign(own_public);

      // Serialise channel public and network signature and length-prefix both
      auto space = own_public.size() + signature.size() + 2 * sizeof(size_t);
      std::vector<uint8_t> serialised_signed_public(space);
      auto data_ = serialised_signed_public.data();
      serialized::write(data_, space, own_public.size());
      serialized::write(data_, space, own_public.data(), own_public.size());
      serialized::write(data_, space, signature.size());
      serialized::write(data_, space, signature.data(), signature.size());

      return serialised_signed_public;
    }

    bool load_peer_signed_public(
      bool complete, const uint8_t* data, size_t size)
    {
      if (status == ESTABLISHED)
      {
        return false;
      }

      auto network_pubk =
        std::make_shared<tls::PublicKey_mbedTLS>(network_kp->public_key_pem());

      auto peer_public_size = serialized::read<size_t>(data, size);
      auto peer_public_start = data;

      if (peer_public_size > size)
      {
        LOG_FAIL_FMT(
          "Peer public key header wants {} bytes, but only {} remain",
          peer_public_size,
          size);
        return false;
      }

      data += peer_public_size;
      size -= peer_public_size;

      auto signature_size = serialized::read<size_t>(data, size);
      auto signature_start = data;

      if (signature_size > size)
      {
        LOG_FAIL_FMT(
          "Signature header wants {} bytes, but only {} remain",
          signature_size,
          size);
        return false;
      }

      if (signature_size < size)
      {
        LOG_FAIL_FMT(
          "Expected signature to use all remaining {} bytes, but only uses "
          "{}",
          size,
          signature_size);
        return false;
      }

      if (!network_pubk->verify(
            peer_public_start,
            peer_public_size,
            signature_start,
            signature_size))
      {
        LOG_FAIL_FMT(
          "node channel peer signature verification failed {}", peer_id);
        return false;
      }

      ctx.load_peer_public(peer_public_start, peer_public_size);

      establish(complete);

      return true;
    }

    void establish(bool complete)
    {
      auto shared_secret = ctx.compute_shared_secret();
      key = std::make_unique<crypto::KeyAesGcm>(shared_secret);
      ctx.free_ctx();
      status = ESTABLISHED;

      if (outgoing_msg.has_value())
      {
        send(
          outgoing_msg->type,
          outgoing_msg->raw_plain,
          outgoing_msg->raw_cipher);
        outgoing_msg.reset();
      }

      LOG_INFO_FMT("node channel with {} is now established", peer_id);

      if (!complete)
      {
        ChannelHeader msg = {ChannelMsg::key_exchange_response, self};
        to_host->write(
          node_outbound,
          peer_id,
          NodeMsgType::channel_msg,
          msg,
          get_signed_public());
      }
    }

    bool send(NodeMsgType msg_type, CBuffer aad, CBuffer plain = nullb)
    {
      if (status != ESTABLISHED)
      {
        try_establish_channel();
        outgoing_msg = OutgoingMsg(msg_type, aad, plain);
        return false;
      }

      RecvNonce nonce(
        send_nonce.fetch_add(1), threading::get_current_thread_id());

      serializer::ByteRange aad_byte_range = {aad.p, aad.n};
      GcmHdr hdr;
      hdr.set_iv_seq(nonce.get_val());

      std::vector<uint8_t> cipher(plain.n);
      key->encrypt(hdr.get_iv(), plain, aad, cipher.data(), hdr.tag);

      to_host->write(
        node_outbound, peer_id, msg_type, aad_byte_range, hdr, cipher);

      return true;
    }

    bool recv_authenticated(CBuffer aad, const uint8_t*& data, size_t& size)
    {
      // Receive authenticated message, modifying data to point to the start of
      // the non-authenticated plaintext payload
      if (status != ESTABLISHED)
      {
        LOG_FAIL_FMT(
          "node channel with {} cannot receive authenticated message: not "
          "yet established",
          peer_id);
        return false;
      }

      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      if (!verify_or_decrypt(hdr, aad))
      {
        LOG_FAIL_FMT("Failed to verify node message from {}", peer_id);
        return false;
      }

      return true;
    }

    bool recv_authenticated_with_load(const uint8_t*& data, size_t& size)
    {
      // Receive authenticated message, modifying data to point to the start of
      // the non-authenticated plaintex payload. data contains payload first,
      // then GCM header

      const uint8_t* data_ = data;
      size_t size_ = size;

      serialized::skip(data_, size_, (size_ - sizeof(GcmHdr)));
      const auto& hdr = serialized::overlay<GcmHdr>(data_, size_);
      size -= sizeof(GcmHdr);

      if (!verify_or_decrypt(hdr, {data, size}))
      {
        LOG_FAIL_FMT("Failed to verify node message from {}", peer_id);
        return false;
      }

      return true;
    }

    std::optional<std::vector<uint8_t>> recv_encrypted(
      CBuffer aad, const uint8_t* data, size_t size)
    {
      // Receive encrypted message, returning the decrypted payload
      if (status != ESTABLISHED)
      {
        LOG_FAIL_FMT(
          "node channel with {} cannot receive encrypted message: not yet "
          "established",
          peer_id);
        return std::nullopt;
      }

      const auto& hdr = serialized::overlay<GcmHdr>(data, size);
      std::vector<uint8_t> plain(size);
      if (!verify_or_decrypt(hdr, aad, {data, size}, plain))
      {
        LOG_FAIL_FMT("Failed to decrypt node message from {}", peer_id);
        return std::nullopt;
      }

      return plain;
    }
  };

  class ChannelManager
  {
  private:
    std::unordered_map<NodeId, std::shared_ptr<Channel>> channels;
    ringbuffer::AbstractWriterFactory& writer_factory;
    tls::KeyPairPtr network_kp;
    NodeId self;
    SpinLock lock;

  public:
    ChannelManager(
      ringbuffer::AbstractWriterFactory& writer_factory_,
      const tls::Pem& network_pkey,
      NodeId self_) :
      writer_factory(writer_factory_),
      network_kp(std::make_shared<tls::KeyPair_mbedTLS>(network_pkey)),
      self(self_)
    {}

    void create_channel(
      NodeId peer_id, const std::string& hostname, const std::string& service)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto search = channels.find(peer_id);
      if (search == channels.end())
      {
        LOG_DEBUG_FMT(
          "Creating new outbound channel to {} ({}:{})",
          peer_id,
          hostname,
          service);
        auto channel = std::make_shared<Channel>(
          writer_factory, network_kp, self, peer_id, hostname, service);
        channels.emplace_hint(search, peer_id, std::move(channel));
      }
      else if (!search->second->is_outgoing())
      {
        // Channel with peer already exists but is incoming. Create host
        // outgoing connection.
        LOG_DEBUG_FMT("Setting existing channel to {} as outgoing", peer_id);
        search->second->set_outgoing(hostname, service);
        return;
      }
    }

    void destroy_channel(NodeId peer_id)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto search = channels.find(peer_id);
      if (search == channels.end())
      {
        LOG_FAIL_FMT(
          "Cannot destroy node channel with {}: channel does not exist",
          peer_id);
        return;
      }

      channels.erase(peer_id);
    }

    void destroy_all_channels()
    {
      std::lock_guard<SpinLock> guard(lock);
      channels.clear();
    }

    void close_all_outgoing()
    {
      std::lock_guard<SpinLock> guard(lock);
      for (auto& c : channels)
      {
        if (c.second->is_outgoing())
        {
          c.second->reset_outgoing();
        }
      }
    }

    std::shared_ptr<Channel> get(NodeId peer_id)
    {
      std::lock_guard<SpinLock> guard(lock);
      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        return search->second;
      }

      // Creating temporary channel that is not outgoing (at least for now)
      channels.try_emplace(
        peer_id,
        std::make_shared<Channel>(writer_factory, network_kp, self, peer_id));
      return channels.at(peer_id);
    }
  };
}

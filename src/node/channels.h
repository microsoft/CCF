// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "entities.h"
#include "nodetypes.h"
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

    RecvNonce(uint64_t nonce_, uint8_t tid_) : nonce(nonce_), tid(tid_) {}
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

  enum ChannelStatus
  {
    INITIATED = 0,
    ESTABLISHED
  };

  class Channel
  {
  private:
    // Used for key exchange
    tls::KeyExchangeContext ctx;
    ChannelStatus status = INITIATED;

    // Notifies the host to create a new outgoing connection
    ringbuffer::WriterPtr to_host;
    NodeId peer_id;
    std::string peer_hostname;
    std::string peer_service;
    bool outgoing;

    // Used for AES GCM authentication/encryption
    std::unique_ptr<crypto::KeyAesGcm> key;

    // Incremented for each tagged/encrypted message
    std::atomic<SeqNo> send_nonce{1};

    // Used to prevent replayed messages.
    // Set to the latest successfully received nonce.
    struct ChannelSeqno
    {
      SeqNo main_thread_seqno;
      SeqNo tid_seqno;
    };
    std::array<ChannelSeqno, threading::ThreadMessaging::max_num_threads>
      local_recv_nonce = {0};

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
      auto& channel_nonce = local_recv_nonce[tid];

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
          "Invalid nonce, possible replay attack, received:{}, last_seen:{}, "
          "recv_nonce.tid:{}",
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

  public:
    Channel(
      ringbuffer::AbstractWriterFactory& writer_factory,
      NodeId peer_id_,
      const std::string& peer_hostname_,
      const std::string& peer_service_) :
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
      ringbuffer::AbstractWriterFactory& writer_factory, NodeId peer_id_) :
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

    std::optional<std::vector<uint8_t>> get_public()
    {
      if (status == ESTABLISHED)
      {
        return {};
      }

      return ctx.get_own_public();
    }

    bool load_peer_public(const uint8_t* bytes, size_t size)
    {
      if (status == ESTABLISHED)
      {
        return false;
      }

      ctx.load_peer_public(bytes, size);
      return true;
    }

    void establish()
    {
      auto shared_secret = ctx.compute_shared_secret();
      key = std::make_unique<crypto::KeyAesGcm>(shared_secret);
      ctx.free_ctx();
      status = ESTABLISHED;
    }

    void free_ctx()
    {
      if (status != ESTABLISHED)
      {
        return;
      }

      ctx.free_ctx();
    }

    void tag(GcmHdr& header, CBuffer aad)
    {
      if (status != ESTABLISHED)
      {
        throw std::logic_error("Channel is not established for tagging");
      }
      RecvNonce nonce(
        send_nonce.fetch_add(1), threading::get_current_thread_id());

      header.set_iv_seq(nonce.get_val());
      key->encrypt(header.get_iv(), nullb, aad, nullptr, header.tag);
    }

    static RecvNonce get_nonce(const GcmHdr& header)
    {
      return RecvNonce(header.get_iv_int());
    }

    bool verify(const GcmHdr& header, CBuffer aad)
    {
      return verify_or_decrypt(header, aad);
    }

    void encrypt(GcmHdr& header, CBuffer aad, CBuffer plain, Buffer cipher)
    {
      if (status != ESTABLISHED)
      {
        throw std::logic_error("Channel is not established for encrypting");
      }

      RecvNonce nonce(
        send_nonce.fetch_add(1), threading::get_current_thread_id());

      header.set_iv_seq(nonce.get_val());
      key->encrypt(header.get_iv(), plain, aad, cipher.p, header.tag);
    }

    bool decrypt(
      const GcmHdr& header, CBuffer aad, CBuffer cipher, Buffer plain)
    {
      return verify_or_decrypt(header, aad, cipher, plain);
    }
  };

  class ChannelManager
  {
  private:
    std::unordered_map<NodeId, Channel> channels;
    ringbuffer::AbstractWriterFactory& writer_factory;
    tls::KeyPairPtr network_kp;

  public:
    ChannelManager(
      ringbuffer::AbstractWriterFactory& writer_factory_,
      const tls::Pem& network_pkey) :
      writer_factory(writer_factory_),
      network_kp(tls::make_key_pair(network_pkey))
    {}

    void create_channel(
      NodeId peer_id, const std::string& hostname, const std::string& service)
    {
      auto search = channels.find(peer_id);
      if (search != channels.end() && !search->second.is_outgoing())
      {
        // Channel with peer already exists but is incoming. Create host
        // outgoing connection.
        search->second.set_outgoing(hostname, service);
        return;
      }

      channels.try_emplace(peer_id, writer_factory, peer_id, hostname, service);
    }

    void destroy_channel(NodeId peer_id)
    {
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

    void close_all_outgoing()
    {
      for (auto& c : channels)
      {
        if (c.second.is_outgoing())
        {
          c.second.reset_outgoing();
        }
      }
    }

    Channel& get(NodeId peer_id)
    {
      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        return search->second;
      }

      // Creating temporary channel that is not outgoing
      channels.try_emplace(peer_id, writer_factory, peer_id);

      return channels.at(peer_id);
    }

    std::optional<std::vector<uint8_t>> get_signed_public(NodeId peer_id)
    {
      const auto own_public_for_peer_ = get(peer_id).get_public();
      if (!own_public_for_peer_.has_value())
      {
        return std::nullopt;
      }

      const auto& own_public_for_peer = own_public_for_peer_.value();

      auto signature = network_kp->sign(own_public_for_peer);

      // Serialise channel public and network signature
      // Length-prefix both
      auto space =
        own_public_for_peer.size() + signature.size() + 2 * sizeof(size_t);
      std::vector<uint8_t> ret(space);
      auto data_ = ret.data();
      serialized::write(data_, space, own_public_for_peer.size());
      serialized::write(
        data_, space, own_public_for_peer.data(), own_public_for_peer.size());
      serialized::write(data_, space, signature.size());
      serialized::write(data_, space, signature.data(), signature.size());

      return ret;
    }

    bool load_peer_signed_public(
      NodeId peer_id, const std::vector<uint8_t>& peer_signed_public)
    {
      auto& channel = get(peer_id);

      // Verify signature
      auto network_pubk = tls::make_public_key(network_kp->public_key_pem());

      auto data = peer_signed_public.data();
      auto data_remaining = peer_signed_public.size();

      auto peer_public_size = serialized::read<size_t>(data, data_remaining);
      auto peer_public_start = data;

      if (peer_public_size > data_remaining)
      {
        LOG_FAIL_FMT(
          "Peer public key header wants {} bytes, but only {} remain",
          peer_public_size,
          data_remaining);
        return false;
      }

      data += peer_public_size;
      data_remaining -= peer_public_size;

      auto signature_size = serialized::read<size_t>(data, data_remaining);
      auto signature_start = data;

      if (signature_size > data_remaining)
      {
        LOG_FAIL_FMT(
          "Signature header wants {} bytes, but only {} remain",
          signature_size,
          data_remaining);
        return false;
      }

      if (signature_size < data_remaining)
      {
        LOG_FAIL_FMT(
          "Expected signature to use all remaining {} bytes, but only uses {}",
          data_remaining,
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

      if (!channel.load_peer_public(peer_public_start, peer_public_size))
      {
        return false;
      }

      channel.establish();

      LOG_INFO_FMT("node channel with {} is now established", peer_id);

      return true;
    }
  };
}

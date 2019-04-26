// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmkey.h"
#include "ds/logger.h"
#include "entities.h"
#include "tls/keyexchange.h"
#include "tls/keypair.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

namespace ccf
{
  using SeqNo = uint64_t;
  using GcmHdr = crypto::GcmHeader<sizeof(SeqNo)>;

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
    ChannelStatus status;

    // Used for AES GCM authentication/encryption
    std::unique_ptr<crypto::KeyAesGcm> key;
    std::atomic<SeqNo> seqNo{0};

  public:
    static constexpr size_t len_public = tls::KeyExchangeContext::len_public;

    Channel() : status(INITIATED) {}

    std::optional<std::vector<uint8_t>> get_public()
    {
      if (status == ESTABLISHED)
        return {};

      return ctx.get_own_public();
    }

    void set_status(ChannelStatus status_)
    {
      status = status_;
    }

    ChannelStatus get_status()
    {
      return status;
    }

    bool load_peer_public(const uint8_t* bytes, size_t size)
    {
      if (status == ESTABLISHED)
        return false;

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
        return;

      ctx.free_ctx();
    }

    void tag(GcmHdr& header, CBuffer aad)
    {
      if (status != ESTABLISHED)
        throw std::logic_error("Channel is not established for tagging");

      header.setIvSeq(seqNo.fetch_add(1));
      key->encrypt(header.getIv(), nullb, aad, nullptr, header.tag);
    }

    bool verify(const GcmHdr& header, CBuffer aad)
    {
      if (status != ESTABLISHED)
        throw std::logic_error("Channel is not established for verifying");

      return key->decrypt(header.getIv(), header.tag, nullb, aad, nullptr);
    }

    void encrypt(GcmHdr& header, CBuffer aad, CBuffer plain, Buffer cipher)
    {
      if (status != ESTABLISHED)
        throw std::logic_error("Channel is not established for encrypting");

      header.setIvSeq(seqNo.fetch_add(1));
      key->encrypt(header.getIv(), plain, aad, cipher.p, header.tag);
    }

    bool decrypt(
      const GcmHdr& header, CBuffer aad, CBuffer cipher, Buffer plain)
    {
      if (status != ESTABLISHED)
        throw std::logic_error("Channel is not established for encrypting");

      return key->decrypt(header.getIv(), header.tag, cipher, aad, plain.p);
    }
  };

  class ChannelManager
  {
  private:
    std::unordered_map<NodeId, std::unique_ptr<Channel>> channels;
    tls::KeyPair network_kp;

  public:
    ChannelManager(const std::vector<uint8_t>& network_pkey) :
      network_kp(network_pkey)
    {}

    Channel& get(NodeId peer_id)
    {
      auto search = channels.find(peer_id);
      if (search != channels.end())
      {
        return *search->second;
      }

      auto channel = std::make_unique<Channel>();
      channels.emplace(peer_id, std::move(channel));
      return *channels[peer_id];
    }

    std::optional<std::vector<uint8_t>> get_signed_public(NodeId peer_id)
    {
      auto own_public_for_peer = get(peer_id).get_public();
      if (!own_public_for_peer.has_value())
        return {};

      auto signature = network_kp.sign(own_public_for_peer.value());

      // Serialise channel public and network signature
      auto space = own_public_for_peer.value().size() + signature.size();
      std::vector<uint8_t> ret(space);
      auto data_ = ret.data();
      serialized::write(
        data_,
        space,
        own_public_for_peer.value().data(),
        own_public_for_peer.value().size());
      serialized::write(data_, space, signature.data(), signature.size());

      return ret;
    }

    bool load_peer_signed_public(
      NodeId peer_id, const std::vector<uint8_t>& peer_signed_public)
    {
      auto& channel = get(peer_id);

      // Verify signature
      tls::PublicKey network_pubk(network_kp.public_key());

      if (!network_pubk.verify(
            peer_signed_public.data(),
            Channel::len_public,
            peer_signed_public.data() + Channel::len_public,
            peer_signed_public.size() - Channel::len_public))
      {
        LOG_FAIL << "node2node peer signature verification failed " << peer_id
                 << std::endl;
        return false;
      }

      // Load peer public
      if (!channel.load_peer_public(
            peer_signed_public.data(), Channel::len_public))
      {
        return false;
      }

      // Channel can be established
      channel.establish();

      LOG_DEBUG << "node2node channel with " << peer_id << " is now established"
                << std::endl;

      return true;
    }
  };
}

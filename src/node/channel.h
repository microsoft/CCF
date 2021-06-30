// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/entity_id.h"
#include "crypto/hash_provider.h"
#include "crypto/key_pair.h"
#include "crypto/symmetric_key.h"
#include "crypto/verifier.h"
#include "ds/hex.h"
#include "ds/logger.h"
#include "ds/serialized.h"
#include "ds/state_machine.h"
#include "entities.h"
#include "node_types.h"
#include "tls/key_exchange.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

// -Wpedantic flags token pasting of __VA_ARGS__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#define CHANNEL_RECV_TRACE(s, ...) \
  LOG_TRACE_FMT("<- {} ({}): " s, peer_id, status.value(), ##__VA_ARGS__)
#define CHANNEL_SEND_TRACE(s, ...) \
  LOG_TRACE_FMT("-> {} ({}): " s, peer_id, status.value(), ##__VA_ARGS__)

namespace ccf
{
  using SendNonce = uint64_t;
  using GcmHdr = crypto::GcmHeader<sizeof(SendNonce)>;

  struct RecvNonce
  {
    uint8_t tid;
    uint64_t nonce : (sizeof(SendNonce) - sizeof(tid)) * CHAR_BIT;

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
    sizeof(RecvNonce) == sizeof(SendNonce), "RecvNonce is the wrong size");

  static inline RecvNonce get_nonce(const GcmHdr& header)
  {
    return RecvNonce(header.get_iv_int());
  }

  enum ChannelStatus
  {
    INACTIVE = 0,
    INITIATED,
    WAITING_FOR_FINAL,
    ESTABLISHED
  };

  class Channel
  {
  public:
#ifndef NDEBUG
    // In debug mode, we use a small message limit to ensure that key rotation
    // is triggered during CI and test runs where we usually wouldn't see enough
    // messages.
    static constexpr size_t default_message_limit = 2048;
#else
    // 2**24.5 as per RFC8446 Section 5.5
    // TODO: Temp debugging step, cause many reconnections
    static constexpr size_t default_message_limit = 100;
#endif

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
    const crypto::Pem& network_cert;
    crypto::KeyPairPtr node_kp;
    const crypto::Pem& node_cert;
    crypto::VerifierPtr peer_cv;
    crypto::Pem peer_cert;

    ringbuffer::WriterPtr to_host;
    NodeId peer_id;

    // Used for key exchange
    tls::KeyExchangeContext kex_ctx;
    ds::StateMachine<ChannelStatus> status;
    static constexpr size_t salt_len = 32;
    static constexpr size_t shared_key_size = 32;
    std::vector<uint8_t> hkdf_salt;
    size_t message_limit = default_message_limit;

    size_t initiation_attempt_nonce = 0;

    // Used for AES GCM authentication/encryption
    std::unique_ptr<crypto::KeyAesGcm> recv_key;
    std::unique_ptr<crypto::KeyAesGcm> send_key;

    // Incremented for each tagged/encrypted message
    std::atomic<SendNonce> send_nonce{1};

    // Used to buffer at most one message sent on the channel before it is
    // established
    // std::optional<OutgoingMsg> outgoing_msg;
    std::vector<OutgoingMsg> outgoing_msgs; // TODO: Temp test

    // Used to prevent replayed messages.
    // Set to the latest successfully received nonce.
    struct ChannelSeqno
    {
      SendNonce main_thread_seqno;
      SendNonce tid_seqno;
    };
    std::array<ChannelSeqno, threading::ThreadMessaging::max_num_threads>
      local_recv_nonce = {{}};

    bool verify_or_decrypt(
      const GcmHdr& header,
      CBuffer aad,
      CBuffer cipher = nullb,
      Buffer plain = {})
    {
      status.expect(ESTABLISHED);

      RecvNonce recv_nonce(header.get_iv_int());
      auto tid = recv_nonce.tid;
      assert(tid < threading::ThreadMessaging::max_num_threads);

      uint16_t current_tid = threading::get_current_thread_id();
      assert(
        current_tid == threading::ThreadMessaging::main_thread ||
        current_tid % threading::ThreadMessaging::thread_count == tid);

      SendNonce* local_nonce;
      if (current_tid == threading::ThreadMessaging::main_thread)
      {
        local_nonce = &local_recv_nonce[tid].main_thread_seqno;
      }
      else
      {
        local_nonce = &local_recv_nonce[tid].tid_seqno;
      }

      CHANNEL_RECV_TRACE(
        "verify_or_decrypt({} bytes, {} bytes) (nonce={})",
        aad.n,
        cipher.n,
        (size_t)recv_nonce.nonce);

      CHANNEL_RECV_TRACE("  aad = {:02x}", fmt::join(aad.p, aad.p + aad.n, ""));
      CHANNEL_RECV_TRACE(
        "  cipher ({} bytes) = {:02x}",
        cipher.n,
        fmt::join(cipher.p, cipher.p + cipher.n, ""));
      CHANNEL_RECV_TRACE("  hdr.iv = {:02x}", fmt::join(header.iv, ""));
      CHANNEL_RECV_TRACE("  hdr.tag = {:02x}", fmt::join(header.tag, ""));

      // Note: We must assume that some messages are dropped, i.e. we may not
      // see every nonce/sequence number, but they must be increasing.

      if (recv_nonce.nonce <= *local_nonce)
      {
        // If the nonce received has already been processed, return
        // See https://github.com/microsoft/CCF/issues/2492 for more details on
        // how this can happen around election time
        LOG_TRACE_FMT(
          "Received past nonce from:{}, received:{}, "
          "last_seen:{}, recv_nonce.tid:{}",
          peer_id,
          reinterpret_cast<uint64_t>(recv_nonce.nonce),
          *local_nonce,
          recv_nonce.tid);
        return false;
      }

      auto ret =
        recv_key->decrypt(header.get_iv(), header.tag, cipher, aad, plain.p);
      if (ret)
      {
        // Set local recv nonce to received nonce only if verification is
        // successful
        *local_nonce = recv_nonce.nonce;
      }

      size_t num_messages = send_nonce + recv_nonce.nonce;
      if (num_messages >= message_limit)
      {
        CHANNEL_RECV_TRACE(
          "Reached message limit ({}+{} >= {}), triggering new key exchange",
          send_nonce,
          (uint64_t)recv_nonce.nonce,
          message_limit);
        reset();
        initiate();
      }

      return ret;
    }

    void send_key_exchange_init()
    {
      std::vector<uint8_t> payload(
        sizeof(ChannelMsg::key_exchange_init) +
        sizeof(initiation_attempt_nonce));

      auto data = payload.data();
      auto size = payload.size();

      serialized::write(data, size, ChannelMsg::key_exchange_init);
      // TODO: Integrity protect
      serialized::write(data, size, initiation_attempt_nonce);

      // TODO: Remove this extra copy?
      const auto ks = get_signed_key_share(true);
      payload.insert(payload.end(), ks.begin(), ks.end());

      CHANNEL_SEND_TRACE(
        "send_key_exchange_init: node serial: {}",
        make_verifier(node_cert)->serial_number());

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound,
        to_host,
        peer_id.value(),
        NodeMsgType::channel_msg,
        self.value(),
        payload);
    }

    void send_key_exchange_response()
    {
      std::vector<uint8_t> payload(
        sizeof(ChannelMsg::key_exchange_response) +
        sizeof(initiation_attempt_nonce));

      auto data = payload.data();
      auto size = payload.size();

      serialized::write(data, size, ChannelMsg::key_exchange_response);
      // TODO: Integrity protect
      serialized::write(data, size, initiation_attempt_nonce);

      auto oks = kex_ctx.get_own_key_share();
      auto serialised_signed_share =
        sign_key_share(oks, false, &kex_ctx.get_peer_key_share());

      // TODO: Remove this extra copy?
      payload.insert(
        payload.end(),
        serialised_signed_share.begin(),
        serialised_signed_share.end());

      CHANNEL_SEND_TRACE(
        "send_key_exchange_response: oks={}, serialised_signed_share={}",
        ds::to_hex(oks),
        ds::to_hex(serialised_signed_share));

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound,
        to_host,
        peer_id.value(),
        NodeMsgType::channel_msg,
        self.value(),
        payload);
    }

    // Called whenever we try to send or receive and the channel is not
    // ESTABLISHED, to trigger new initiation attempts or resends of previous
    // protocol message
    void advance_connection_attempt()
    {
      // TODO: Resending here is potentially very expensive. Work out if we need
      // resends or could avoid it, and see if we can find a better heuristic
      // for resending than "every time we get unexpected junk and we're not yet
      // ESTABLISHED"
      switch (status.value())
      {
        case (INACTIVE):
        {
          // We have no key and believe no key exchange is in process - start a
          // new iteration of the key exchange protocol
          initiate();
          break;
        }

        case (INITIATED):
        {
          // We initiated with them but are still waiting for a response -
          // resend the same init message in case they missed it
          send_key_exchange_init();
          break;
        }

        case (WAITING_FOR_FINAL):
        {
          // We received an init, and responded, but are still waiting for a
          // final - resend the same response in case they missed it
          send_key_exchange_response();
          break;
        }

        case (ESTABLISHED):
        {
          // TODO: How do we resend FINAL, if it looks like they missed it?
          // TODO: Consider an ESTABLISHED_TENTATIVE state, where we've sent
          // FINAL but still have the state to resend it? Can resend if they
          // respond again, and otherwise we encrypt with our current key?
          throw std::logic_error(
            "advance_connection_attempt() should never be called on an "
            "ESTABLISHED connection");
          break;
        }
      }
    }

    bool recv_key_exchange_init(
      const uint8_t* data, size_t size, bool priority = false)
    {
      const auto initiation_attempt = serialized::read<size_t>(data, size);
      CHANNEL_RECV_TRACE(
        "recv_key_exchange_init({} bytes, {}) ({} vs {})",
        size,
        priority,
        initiation_attempt,
        initiation_attempt_nonce);

      if (initiation_attempt < initiation_attempt_nonce)
      {
        // Ignoring older attempt
        return false;
      }
      else if (initiation_attempt > initiation_attempt_nonce)
      {
        // Accepting newer attempt - updating to its nonce
        reset();
        initiation_attempt_nonce = initiation_attempt;
      }
      else
      {
        // Received in the same attempt as we're currently in
        if (status.check(INITIATED))
        {
          // Both nodes tried to initiate the channel, the one with priority
          // wins.
          if (!priority)
          {
            return true;
          }
          else
          {
            reset();
          }
        }
        else if (!status.check(INACTIVE))
        {
          // Replaying an earlier message from the current attempt - ignore
          return false;
        }
      }

      status.expect(INACTIVE);

      size_t peer_version = serialized::read<size_t>(data, size);
      CBuffer ks = extract_buffer(data, size);
      CBuffer sig = extract_buffer(data, size);
      CBuffer pc = extract_buffer(data, size);
      CBuffer salt = extract_buffer(data, size);

      CHANNEL_RECV_TRACE(
        "recv_key_exchange_init: version={} ks={} sig={} pc={} salt={}",
        peer_version,
        ds::to_hex(ks),
        ds::to_hex(sig),
        ds::to_hex(pc),
        ds::to_hex(salt));

      if (size != 0)
      {
        LOG_FAIL_FMT("{} exccess bytes remaining", size);
        return false;
      }

      hkdf_salt = {salt.p, salt.p + salt.n};

      if (peer_version != protocol_version)
      {
        LOG_FAIL_FMT(
          "Protocol version mismatch (node={}, peer={})",
          protocol_version,
          peer_version);
        return false;
      }

      if (ks.n == 0 || sig.n == 0)
      {
        return false;
      }

      if (!verify_peer_certificate(pc) || !verify_peer_signature(ks, sig))
      {
        return false;
      }

      kex_ctx.load_peer_key_share(ks);

      status.advance(WAITING_FOR_FINAL);

      // We are the responder and we return a signature over both public key
      // shares back to the initiator
      send_key_exchange_response();

      return true;
    }

    bool recv_key_exchange_response(const uint8_t* data, size_t size)
    {
      const auto initiation_attempt = serialized::read<size_t>(data, size);
      CHANNEL_RECV_TRACE(
        "recv_key_exchange_response({} bytes) ({} vs {})",
        size,
        initiation_attempt,
        initiation_attempt_nonce);

      if (initiation_attempt < initiation_attempt_nonce)
      {
        // Ignoring older attempt
        return false;
      }
      else if (initiation_attempt > initiation_attempt_nonce)
      {
        // Received a _response_ from a newer attempt, meaning this node doesn't
        // think it sent any comparable _init_. Looks malicious! Ignore it
        return false;
      }

      status.expect(INITIATED);

      size_t peer_version = serialized::read<size_t>(data, size);
      CBuffer ks = extract_buffer(data, size);
      CBuffer sig = extract_buffer(data, size);
      CBuffer pc = extract_buffer(data, size);

      CHANNEL_RECV_TRACE(
        "recv_key_exchange_response: version={} ks={} sig={} pc={}",
        peer_version,
        ds::to_hex(ks),
        ds::to_hex(sig),
        ds::to_hex(pc));

      if (size != 0)
      {
        LOG_FAIL_FMT("{} exccess bytes remaining", size);
        return false;
      }

      if (peer_version != protocol_version)
      {
        LOG_FAIL_FMT(
          "Protocol version mismatch (node={}, peer={})",
          protocol_version,
          peer_version);
        return false;
      }

      if (ks.n == 0 || sig.n == 0)
      {
        return false;
      }

      if (!verify_peer_certificate(pc))
      {
        return false;
      }

      // We are the initiator and expect a signature over both key shares
      std::vector<uint8_t> t = {ks.p, ks.p + ks.n};
      auto oks = kex_ctx.get_own_key_share();
      t.insert(t.end(), oks.begin(), oks.end());

      if (!verify_peer_signature(t, sig))
      {
        // TODO: Should we close the channel here and retry? Are they malicious
        // or confused, and how does that change our decision?
        return false;
      }

      kex_ctx.load_peer_key_share(ks);

      std::vector<uint8_t> payload(
        sizeof(ChannelMsg::key_exchange_final) +
        sizeof(initiation_attempt_nonce));

      {
        auto payload_data = payload.data();
        auto payload_size = payload.size();

        serialized::write(
          payload_data, payload_size, ChannelMsg::key_exchange_final);
        // TODO: Integrity protect
        serialized::write(payload_data, payload_size, initiation_attempt_nonce);
      }

      // Sign the peer's key share
      auto signature = node_kp->sign(ks);

      // Serialise signature with length-prefix
      auto space = signature.size() + 1 * sizeof(size_t);
      std::vector<uint8_t> serialised_signature(space);
      auto data_ = serialised_signature.data();
      serialized::write(data_, space, signature.size());
      serialized::write(data_, space, signature.data(), signature.size());

      // TODO: Remove this extra copy?
      payload.insert(
        payload.end(),
        serialised_signature.begin(),
        serialised_signature.end());

      CHANNEL_SEND_TRACE(
        "key_exchange_final: ks={}, serialised_signed_key_share={}",
        ds::to_hex(ks),
        ds::to_hex(serialised_signature));

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound,
        to_host,
        peer_id.value(),
        NodeMsgType::channel_msg,
        self.value(),
        payload);

      establish();

      return true;
    }

    bool recv_key_exchange_final(const uint8_t* data, size_t size)
    {
      const auto initiation_attempt = serialized::read<size_t>(data, size);
      CHANNEL_RECV_TRACE(
        "recv_key_exchange_final({} bytes) ({} vs {})",
        size,
        initiation_attempt,
        initiation_attempt_nonce);

      if (initiation_attempt < initiation_attempt_nonce)
      {
        // Ignoring older attempt
        return false;
      }
      else if (initiation_attempt > initiation_attempt_nonce)
      {
        // Same as in `recv_key_exchange_response` - received a message claiming
        // to respond to something we never sent. Ignore it
        return false;
      }

      status.expect(WAITING_FOR_FINAL);

      auto oks = kex_ctx.get_own_key_share();

      CBuffer sig = extract_buffer(data, size);

      if (!verify_peer_signature(oks, sig))
      {
        // TODO: Should we close the channel here and retry? Are they malicious
        // or confused, and how does that change our decision?
        return false;
      }

      establish();

      return true;
    }

  public:
    static constexpr size_t protocol_version =
      2; // TODO: Need to bump this to add initiation attempt nonces! Should try
         // to be compatible with old nodes...

    Channel(
      ringbuffer::AbstractWriterFactory& writer_factory,
      const crypto::Pem& network_cert_,
      crypto::KeyPairPtr node_kp_,
      const crypto::Pem& node_cert_,
      const NodeId& self_,
      const NodeId& peer_id_,
      size_t message_limit_ = default_message_limit) :
      self(self_),
      network_cert(network_cert_),
      node_kp(node_kp_),
      node_cert(node_cert_),
      to_host(writer_factory.create_writer_to_outside()),
      peer_id(peer_id_),
      status(fmt::format("Channel to {}", peer_id_), INACTIVE),
      message_limit(message_limit_)
    {
      auto e = crypto::create_entropy();
      hkdf_salt = e->random(salt_len);
    }

    ~Channel()
    {
      // TODO: Send a close message now?
    }

    ChannelStatus get_status()
    {
      return status.value();
    }

    std::vector<uint8_t> sign_key_share(
      const std::vector<uint8_t>& ks,
      bool with_salt = false,
      const std::vector<uint8_t>* extra = nullptr)
    {
      std::vector<uint8_t> t = ks;

      if (extra)
      {
        t.insert(t.end(), extra->begin(), extra->end());
      }

      auto signature = node_kp->sign(t);

      // Serialise channel key share, signature, and certificate and
      // length-prefix them
      auto space =
        ks.size() + signature.size() + node_cert.size() + 4 * sizeof(size_t);
      if (with_salt)
      {
        space += hkdf_salt.size() + sizeof(size_t);
      }
      std::vector<uint8_t> serialised_signed_key_share(space);
      auto data_ = serialised_signed_key_share.data();
      serialized::write(data_, space, protocol_version);
      serialized::write(data_, space, ks.size());
      serialized::write(data_, space, ks.data(), ks.size());
      serialized::write(data_, space, signature.size());
      serialized::write(data_, space, signature.data(), signature.size());
      serialized::write(data_, space, node_cert.size());
      serialized::write(data_, space, node_cert.data(), node_cert.size());
      if (with_salt)
      {
        serialized::write(data_, space, hkdf_salt.size());
        serialized::write(data_, space, hkdf_salt.data(), hkdf_salt.size());
      }

      return serialised_signed_key_share;
    }

    std::vector<uint8_t> get_signed_key_share(bool with_salt)
    {
      return sign_key_share(kex_ctx.get_own_key_share(), with_salt);
    }

    CBuffer extract_buffer(const uint8_t*& data, size_t& size) const
    {
      if (size == 0)
      {
        return {};
      }

      auto sz = serialized::read<size_t>(data, size);
      CBuffer r(data, sz);

      if (r.n > size)
      {
        LOG_FAIL_FMT(
          "Buffer header wants {} bytes, but only {} remain", r.n, size);
        r.n = 0;
      }
      else
      {
        data += r.n;
        size -= r.n;
      }

      return r;
    }

    bool verify_peer_certificate(CBuffer pc)
    {
      if (pc.n != 0)
      {
        peer_cert = crypto::Pem(pc);
        peer_cv = crypto::make_verifier(peer_cert);

        if (!peer_cv->verify_certificate({&network_cert}))
        {
          LOG_FAIL_FMT("Peer certificate verification failed");
          reset();
          return false;
        }

        LOG_TRACE_FMT(
          "New peer certificate: {}\n{}",
          peer_cv->serial_number(),
          peer_cert.str());
      }

      return true;
    }

    bool verify_peer_signature(CBuffer msg, CBuffer sig)
    {
      LOG_TRACE_FMT(
        "Verifying peer signature with peer certificate serial {}",
        peer_cv ? peer_cv->serial_number() : "no peer_cv!");

      if (!peer_cv || !peer_cv->verify(msg, sig))
      {
        LOG_FAIL_FMT(
          "Node channel peer signature verification failed for {} with "
          "certificate serial {}",
          peer_id,
          peer_cv->serial_number());
        return false;
      }

      return true;
    }

    // Protocol overview:
    //
    // initiate()
    // > key_exchange_init message
    // recv_key_exchange_init() [by responder]
    // < key_exchange_response message
    // recv_key_exchange_response() [by initiator]
    // > key_exchange_final message
    // recv_key_exchange_final() [by responder]
    // both reach status == ESTABLISHED

    void establish()
    {
      auto shared_secret = kex_ctx.compute_shared_secret();

      {
        const std::string label_from = peer_id.value() + self.value();
        const auto key_bytes = crypto::hkdf(
          crypto::MDType::SHA256,
          shared_key_size,
          shared_secret,
          hkdf_salt,
          {label_from.begin(), label_from.end()});
        recv_key = crypto::make_key_aes_gcm(key_bytes);
      }

      {
        const std::string label_to = self.value() + peer_id.value();
        const auto key_bytes = crypto::hkdf(
          crypto::MDType::SHA256,
          shared_key_size,
          shared_secret,
          hkdf_salt,
          {label_to.begin(), label_to.end()});
        send_key = crypto::make_key_aes_gcm(key_bytes);
      }

      kex_ctx.free_ctx();
      send_nonce = 1;
      for (size_t i = 0; i < local_recv_nonce.size(); i++)
      {
        local_recv_nonce[i].main_thread_seqno = 0;
        local_recv_nonce[i].tid_seqno = 0;
      }

      status.advance(ESTABLISHED);
      LOG_INFO_FMT("Node channel with {} is now established.", peer_id);

      auto node_cv = make_verifier(node_cert);
      LOG_TRACE_FMT(
        "Node certificate serial numbers: node={} peer={}",
        node_cv->serial_number(),
        peer_cv->serial_number());

      if (!outgoing_msgs.empty())
      {
        for (const auto& outgoing_msg : outgoing_msgs)
        {
          send(
            outgoing_msg.type,
            outgoing_msg.raw_plain,
            outgoing_msg.raw_cipher);
        }
        outgoing_msgs.clear();
      }
    }

    void initiate()
    {
      LOG_INFO_FMT("Initiating node channel with {}.", peer_id);

      initiation_attempt_nonce++;

      // Begin with new key exchange
      kex_ctx.reset();
      peer_cert = {};
      peer_cv.reset();

      auto e = crypto::create_entropy();
      hkdf_salt = e->random(salt_len);

      status.expect(INACTIVE);
      status.advance(INITIATED);

      send_key_exchange_init();
    }

    bool send(NodeMsgType type, CBuffer aad, CBuffer plain = nullb)
    {
      if (!status.check(ESTABLISHED))
      {
        advance_connection_attempt();
        outgoing_msgs.push_back(OutgoingMsg(type, aad, plain));
        return false;
      }

      RecvNonce nonce(
        send_nonce.fetch_add(1), threading::get_current_thread_id());

      GcmHdr gcm_hdr;
      gcm_hdr.set_iv_seq(nonce.get_val());

      assert(send_key);

      std::vector<uint8_t> cipher(plain.n);
      send_key->encrypt(
        gcm_hdr.get_iv(), plain, aad, cipher.data(), gcm_hdr.tag);

      // TODO: Remove these unnecessary copies
      std::vector<uint8_t> payload(aad.p, aad.p + aad.n);

      const auto gcm_hdr_serialised = gcm_hdr.serialise();
      payload.insert(
        payload.end(), gcm_hdr_serialised.begin(), gcm_hdr_serialised.end());

      payload.insert(payload.end(), cipher.begin(), cipher.end());

      CHANNEL_SEND_TRACE(
        "send({}, {} bytes, {} bytes) (nonce={})",
        (size_t)type,
        aad.n,
        plain.n,
        (size_t)nonce.nonce);

      CHANNEL_SEND_TRACE("  hdr.iv = {:02x}", fmt::join(gcm_hdr.iv, ""));
      CHANNEL_SEND_TRACE("  hdr.tag = {:02x}", fmt::join(gcm_hdr.tag, ""));
      CHANNEL_SEND_TRACE(
        "  cipher ({} bytes) = {:02x}", cipher.size(), fmt::join(cipher, ""));
      CHANNEL_SEND_TRACE(
        "  payload ({} bytes) = {:02x}",
        payload.size(),
        fmt::join(payload, ""));

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound, to_host, peer_id.value(), type, self.value(), payload);

      return true;
    }

    bool recv_authenticated(CBuffer aad, const uint8_t*& data, size_t& size)
    {
      // Receive authenticated message, modifying data to point to the start of
      // the non-authenticated plaintext payload
      if (!status.check(ESTABLISHED))
      {
        LOG_INFO_FMT(
          "Node channel with {} cannot receive authenticated message: not "
          "established, status={}",
          peer_id,
          status.value());
        advance_connection_attempt();
        return false;
      }

      GcmHdr hdr;
      hdr.deserialise(data, size);

      CHANNEL_RECV_TRACE(" AAA");

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
      // the non-authenticated plaintext payload. data contains payload first,
      // then GCM header

      if (!status.check(ESTABLISHED))
      {
        LOG_INFO_FMT(
          "node channel with {} cannot receive authenticated with payload "
          "message: not established, status={}",
          peer_id,
          status.value());
        advance_connection_attempt();
        return false;
      }

      GcmHdr hdr;
      hdr.deserialise(data, size);

      CHANNEL_RECV_TRACE(" BBB");

      if (!verify_or_decrypt(hdr, {data, size}))
      {
        LOG_FAIL_FMT("Failed to verify node message from {}", peer_id);
        return false;
      }

      return true;
    }

    std::optional<std::vector<uint8_t>> recv_encrypted(
      CBuffer aad, const uint8_t*& data, size_t& size)
    {
      // Receive encrypted message, returning the decrypted payload
      if (!status.check(ESTABLISHED))
      {
        LOG_INFO_FMT(
          "Node channel with {} cannot receive encrypted message: not "
          "established, status={}",
          peer_id,
          status.value());
        advance_connection_attempt();
        return std::nullopt;
      }

      LOG_TRACE_FMT("Size before reading GcmHdr = {}", size);
      GcmHdr hdr;
      hdr.deserialise(data, size);
      LOG_TRACE_FMT("Size after reading GcmHdr = {}", size);

      CHANNEL_RECV_TRACE(" CCC");

      std::vector<uint8_t> plain(size);
      if (!verify_or_decrypt(hdr, aad, {data, size}, plain))
      {
        LOG_FAIL_FMT("Failed to decrypt node message from {}", peer_id);
        return std::nullopt;
      }

      return plain;
    }

    void close_channel()
    {
      reset();
      outgoing_msgs.clear();
      ++initiation_attempt_nonce;
    }

    void reset()
    {
      LOG_INFO_FMT("Resetting channel with {}", peer_id);

      status.advance(INACTIVE);
      kex_ctx.reset();
      peer_cert = {};
      peer_cv.reset();
      recv_key.reset();
      send_key.reset();

      auto e = crypto::create_entropy();
      hkdf_salt = e->random(salt_len);
    }

    bool recv_key_exchange_message(const uint8_t* data, size_t size)
    {
      try
      {
        auto chmsg = serialized::read<ChannelMsg>(data, size);
        switch (chmsg)
        {
          case key_exchange_init:
          {
            // In the case of concurrent key_exchange_init's from both nodes,
            // the one with the lower ID wins.
            return recv_key_exchange_init(data, size, self < peer_id);
          }

          case key_exchange_response:
          {
            return recv_key_exchange_response(data, size);
          }

          case key_exchange_final:
          {
            return recv_key_exchange_final(data, size);
          }

          default:
          {
            throw std::runtime_error(fmt::format(
              "Received message with initial bytes {} from {} - not recognised "
              "as a key exchange message",
              chmsg,
              peer_id));
          }
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_EXC(e.what());
        return false;
      }
    }
  };
}

#pragma clang diagnostic pop

namespace fmt
{
  template <>
  struct formatter<ccf::ChannelStatus>
  {
    template <typename ParseContext>
    constexpr auto parse(ParseContext& ctx)
    {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ccf::ChannelStatus& cs, FormatContext& ctx)
    {
      char const* s = "Unknown";
      switch (cs)
      {
        case (ccf::INACTIVE):
        {
          s = "INACTIVE";
          break;
        }
        case (ccf::INITIATED):
        {
          s = "INITIATED";
          break;
        }
        case (ccf::WAITING_FOR_FINAL):
        {
          s = "WAITING_FOR_FINAL";
          break;
        }
        case (ccf::ESTABLISHED):
        {
          s = "ESTABLISHED";
          break;
        }
      }
      return format_to(ctx.out(), s);
    }
  };
}

#undef CHANNEL_TRACE_FMT
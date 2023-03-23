// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/entropy.h"
#include "ccf/crypto/hkdf.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "ccf/crypto/verifier.h"
#include "ccf/ds/ccf_exception.h"
#include "ccf/ds/hex.h"
#include "ccf/ds/logger.h"
#include "ccf/entity_id.h"
#include "crypto/key_exchange.h"
#include "ds/serialized.h"
#include "ds/state_machine.h"
#include "ds/thread_messaging.h"
#include "enclave/enclave_time.h"
#include "node_types.h"

#include <iostream>
#include <map>
#include <openssl/crypto.h>

// -Wpedantic flags token pasting of __VA_ARGS__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"

#define CHANNEL_RECV_TRACE(s, ...) \
  LOG_TRACE_FMT("<- {} ({}): " s, peer_id, status.value(), ##__VA_ARGS__)
#define CHANNEL_SEND_TRACE(s, ...) \
  LOG_TRACE_FMT("-> {} ({}): " s, peer_id, status.value(), ##__VA_ARGS__)

#define CHANNEL_RECV_FAIL(s, ...) \
  LOG_FAIL_FMT("<- {} ({}): " s, peer_id, status.value(), ##__VA_ARGS__)
#define CHANNEL_SEND_FAIL(s, ...) \
  LOG_FAIL_FMT("-> {} ({}): " s, peer_id, status.value(), ##__VA_ARGS__)

namespace ccf
{
  enum ChannelStatus
  {
    INACTIVE = 0,
    INITIATED,
    WAITING_FOR_FINAL,
    ESTABLISHED
  };
}

FMT_BEGIN_NAMESPACE
template <>
struct formatter<ccf::ChannelStatus>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ChannelStatus& cs, FormatContext& ctx) const
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

    return format_to(ctx.out(), "{}", s);
  }
};
FMT_END_NAMESPACE

namespace ccf
{
  using MsgNonce = uint64_t;
  using GcmHdr = crypto::FixedSizeGcmHeader<sizeof(MsgNonce)>;

  // Receive nonces were previously stored per-thread. For backwards
  // compatibility (live communication with nodes still using this format), we
  // maintain this serialization struct, but with thread ID (tid) always set to
  // 0
  struct WireNonce
  {
    const uint8_t tid = 0;
    uint64_t nonce : (sizeof(MsgNonce) - sizeof(tid)) * CHAR_BIT;

    WireNonce(uint64_t nonce_) : nonce(nonce_) {}

    uint64_t get_val() const
    {
      return *reinterpret_cast<const uint64_t*>(this);
    }
  };
  static_assert(
    sizeof(WireNonce) == sizeof(MsgNonce), "WireNonce is the wrong size");

  // Static helper functions for serialization/deserialization
  namespace
  {
    static inline WireNonce get_wire_nonce(const GcmHdr& header)
    {
      return *reinterpret_cast<const WireNonce*>(header.iv.data());
    }

    template <typename T>
    static inline void append_value(std::vector<uint8_t>& target, const T& t)
    {
      const auto size_before = target.size();
      auto size = sizeof(t);
      target.resize(size_before + size);
      auto data = target.data() + size_before;
      serialized::write(data, size, t);
    }

    static inline void append_buffer(
      std::vector<uint8_t>& target, std::span<const uint8_t> src)
    {
      const auto size_before = target.size();
      auto size = src.size() + sizeof(src.size());
      target.resize(size_before + size);
      auto data = target.data() + size_before;
      serialized::write(data, size, src.size());
      serialized::write(data, size, src.data(), src.size());
    }
  }

  class KeyExchangeProtocol
  {};

  // Key exchange states are:
  // - Have nothing
  // - Initiated (have my own share)
  // - Have their share and my share (received init, or received response)
  // - => Have shared secret
  // - Know that THEY have shared secret (received response or final)
  // As soon as we have both shares, we update our send key
  // As soon as we know that they have shared secret, we update our recv key
  // Note this assumes that the key exchange messages are reliably delivered,
  // else we switch keys without telling the peer that we did.

  class Channel
  {
  public:
    static std::chrono::microseconds min_gap_between_initiation_attempts;

  private:
    struct OutgoingMsg
    {
      NodeMsgType type;
      std::vector<uint8_t> raw_aad; // To be integrity-protected
      std::vector<uint8_t> raw_plain; // To be encrypted

      OutgoingMsg(
        NodeMsgType msg_type,
        std::span<const uint8_t> raw_aad_,
        std::span<const uint8_t> raw_plain_) :
        type(msg_type),
        raw_aad(raw_aad_.begin(), raw_aad_.end()),
        raw_plain(raw_plain_.begin(), raw_plain_.end())
      {}
    };

    NodeId self;
    const crypto::Pem& service_cert;
    crypto::KeyPairPtr node_kp;
    const crypto::Pem& node_cert;
    crypto::VerifierPtr peer_cv;
    crypto::Pem peer_cert;

    ringbuffer::WriterPtr to_host;
    NodeId peer_id;

    // Used for key exchange
    tls::KeyExchangeContext kex_ctx;
    ds::StateMachine<ChannelStatus> status;
    std::chrono::microseconds last_initiation_time;
    static constexpr size_t salt_len = 32;
    static constexpr size_t shared_key_size = 32;
    std::vector<uint8_t> hkdf_salt;
    size_t message_limit;

    // Used for AES GCM authentication/encryption
    std::unique_ptr<crypto::KeyAesGcm> recv_key = nullptr;
    std::unique_ptr<crypto::KeyAesGcm> send_key = nullptr;

    // Incremented for each tagged/encrypted message
    std::atomic<MsgNonce> send_nonce{1};

    // Used to buffer at most one message sent on the channel before it is
    // established
    std::optional<OutgoingMsg> outgoing_consensus_msg;

    // Used to buffer a small number of messages sent on the channel before it
    // is established. If this queue fills, then additional send attempts while
    // the channel is still being established will not be buffered, and the
    // caller should react appropriately.
    static constexpr size_t outgoing_forwarding_queue_size = 10;
    std::vector<OutgoingMsg> outgoing_forwarding_msgs;

    // Used to prevent replayed messages.
    // Set to the latest successfully received nonce.
    MsgNonce local_recv_nonce = {0};

    void check_message_limit()
    {
      // At half message limit, trigger a new key exchange.
      // At hard message limit, drop existing keys, ensuring no further
      // communication until fresh keys have been exchanged
      const auto lower_limit = message_limit / 2;
      size_t num_messages = send_nonce + local_recv_nonce;
      if (num_messages >= lower_limit && status.check(ESTABLISHED))
      {
        CHANNEL_RECV_TRACE(
          "Reached message limit ({}+{} >= {}), triggering new key exchange",
          send_nonce,
          local_recv_nonce,
          lower_limit);
        reset_key_exchange();
        initiate();
      }
      else if (num_messages >= message_limit)
      {
        CHANNEL_RECV_TRACE(
          "Reached hard message limit ({}+{} >= {}), dropping previous keys",
          send_nonce,
          local_recv_nonce,
          message_limit);

        send_key = nullptr;
        recv_key = nullptr;
      }
    }

    bool decrypt(
      const GcmHdr& header,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> cipher,
      std::vector<uint8_t>& plain)
    {
      if (recv_key == nullptr)
      {
        throw std::logic_error("Tried to decrypt, but have no receive key");
      }

      auto wire_nonce = get_wire_nonce(header);
      auto recv_nonce = wire_nonce.nonce;

      CHANNEL_RECV_TRACE(
        "decrypt({} bytes, {} bytes) (nonce={})",
        aad.size(),
        cipher.size(),
        recv_nonce);

      // Note: We must assume that some messages are dropped, i.e. we may not
      // see every nonce/sequence number, but they must be increasing.

      if (recv_nonce <= local_recv_nonce)
      {
        // If the nonce received has already been processed, return
        // See https://github.com/microsoft/CCF/issues/2492 for more details on
        // how this can happen around election time
        CHANNEL_RECV_TRACE(
          "Received past nonce, received:{}, "
          "last_seen:{}",
          recv_nonce,
          local_recv_nonce);
        return false;
      }

      auto ret =
        recv_key->decrypt(header.get_iv(), header.tag, cipher, aad, plain);
      if (ret)
      {
        // Set local recv nonce to received nonce only if verification is
        // successful
        local_recv_nonce = recv_nonce;
      }

      check_message_limit();

      return ret;
    }

    bool verify(const GcmHdr& header, std::span<const uint8_t> aad)
    {
      std::vector<uint8_t> empty_plaintext;
      return decrypt(header, aad, {}, empty_plaintext);
    }

    void send_key_exchange_init()
    {
      std::vector<uint8_t> payload;
      {
        append_value(payload, ChannelMsg::key_exchange_init);
        append_value(payload, protocol_version);
        append_buffer(payload, kex_ctx.get_own_key_share());
        auto signature = node_kp->sign(kex_ctx.get_own_key_share());
        append_buffer(payload, signature);
        append_buffer(
          payload,
          std::span<const uint8_t>(node_cert.data(), node_cert.size()));
        append_buffer(payload, hkdf_salt);
      }

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
      std::vector<uint8_t> signature;
      {
        auto to_sign = kex_ctx.get_own_key_share();
        const auto& peer_ks = kex_ctx.get_peer_key_share();
        to_sign.insert(to_sign.end(), peer_ks.begin(), peer_ks.end());
        signature = node_kp->sign(to_sign);
      }

      std::vector<uint8_t> payload;
      {
        append_value(payload, ChannelMsg::key_exchange_response);
        append_value(payload, protocol_version);
        append_buffer(payload, kex_ctx.get_own_key_share());
        append_buffer(payload, signature);
        append_buffer(
          payload,
          std::span<const uint8_t>(node_cert.data(), node_cert.size()));
      }

      CHANNEL_SEND_TRACE(
        "send_key_exchange_response: oks={}, serialised_signed_share={}",
        ds::to_hex(kex_ctx.get_own_key_share()),
        ds::to_hex(payload));

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound,
        to_host,
        peer_id.value(),
        NodeMsgType::channel_msg,
        self.value(),
        payload);
    }

    void send_key_exchange_final()
    {
      std::vector<uint8_t> payload;
      {
        append_value(payload, ChannelMsg::key_exchange_final);
        // append_value(payload, protocol_version); // Not sent by
        // current protocol!
        auto signature = node_kp->sign(kex_ctx.get_peer_key_share());
        append_buffer(payload, signature);
      }

      CHANNEL_SEND_TRACE(
        "key_exchange_final: ks={}, serialised_signed_key_share={}",
        ds::to_hex(kex_ctx.get_peer_key_share()),
        ds::to_hex(payload));

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound,
        to_host,
        peer_id.value(),
        NodeMsgType::channel_msg,
        self.value(),
        payload);
    }

    void advance_connection_attempt()
    {
      if (status.check(INACTIVE))
      {
        // We have no key and believe no key exchange is in process - start a
        // new iteration of the key exchange protocol
        initiate();
      }
      else if (status.check(INITIATED))
      {
        const auto time_since_initiated =
          ccf::get_enclave_time() - last_initiation_time;
        if (time_since_initiated >= min_gap_between_initiation_attempts)
        {
          // If this node attempts to initiate too early when the peer node
          // starts up, they will never receive the init message (they drop it
          // if it arrives too early in their state machine). The same state
          // could also occur later, if the initiate message is lost in transit.
          // So sometimes this node needs to re-initiate. However, if this node
          // sends too fast before the channel is established, and each send
          // generates a new handshake, it may constantly generate new handshake
          // attempts and never succeed. Additionally, when talking to peers
          // using the old channel behaviour, this node should try to avoid
          // confusing them by sending multiple adjacent initiate requests -
          // they will only process the first one they receive. To avoid these
          // problems with initiation spam, we have a minimum delay between
          // initiation attempts. This should be low enough to get reasonable
          // liveness (re-attempt connections in the presence of dropped
          // messages), but high enough to give successful roundtrips a chance
          // to complete.
          initiate();
        }
      }
    }

    bool recv_key_exchange_init(
      const uint8_t* data, size_t size, bool they_have_priority = false)
    {
      CHANNEL_RECV_TRACE(
        "recv_key_exchange_init({} bytes, {})", size, they_have_priority);

      // Parse fields from incoming message
      size_t peer_version = serialized::read<size_t>(data, size);
      if (peer_version != protocol_version)
      {
        CHANNEL_RECV_FAIL(
          "Protocol version mismatch (node={}, peer={})",
          protocol_version,
          peer_version);
        return false;
      }

      auto ks = extract_span(data, size);
      if (ks.empty())
      {
        CHANNEL_RECV_FAIL("Empty keyshare");
        return false;
      }

      auto sig = extract_span(data, size);
      if (sig.empty())
      {
        CHANNEL_RECV_FAIL("Empty signature");
        return false;
      }

      auto pc = extract_span(data, size);
      if (pc.empty())
      {
        CHANNEL_RECV_FAIL("Empty cert");
        return false;
      }

      auto salt = extract_span(data, size);
      if (salt.empty())
      {
        CHANNEL_RECV_FAIL("Empty salt");
        return false;
      }

      if (size != 0)
      {
        CHANNEL_RECV_FAIL("{} exccess bytes remaining", size);
        return false;
      }

      // Validate cert and signature in message
      crypto::Pem cert;
      crypto::VerifierPtr verifier;
      if (!verify_peer_certificate(pc, cert, verifier))
      {
        CHANNEL_RECV_FAIL(
          "Peer certificate verification failed - recv_key_exchange_init "
          "failed to verify peer cert:\n{}\nUsing trusted service "
          "certificate:\n{}",
          cert.str(),
          service_cert.str());
        return false;
      }

      if (!verify_peer_signature(ks, sig, verifier))
      {
        return false;
      }

      // Both nodes tried to initiate the channel, the one with priority
      // wins.
      if (status.check(INITIATED) && !they_have_priority)
      {
        CHANNEL_RECV_TRACE("Ignoring lower priority key init");
        return true;
      }
      else
      {
        // Whatever else we _were_ doing, we've received a valid init from them
        // - reset to use it
        if (status.check(ESTABLISHED))
        {
          kex_ctx.reset();
        }
        peer_cert = cert;
        peer_cv = verifier;
      }

      CHANNEL_RECV_TRACE(
        "recv_key_exchange_init: version={} ks={} sig={} pc={} salt={}",
        peer_version,
        ds::to_hex(ks),
        ds::to_hex(sig),
        ds::to_hex(pc),
        ds::to_hex(salt));

      hkdf_salt = {salt.data(), salt.data() + salt.size()};

      kex_ctx.load_peer_key_share(ks);

      update_send_key();

      status.advance(WAITING_FOR_FINAL);

      // We are the responder and we return a signature over both public key
      // shares back to the initiator
      send_key_exchange_response();

      return true;
    }

    bool recv_key_exchange_response(const uint8_t* data, size_t size)
    {
      CHANNEL_RECV_TRACE("recv_key_exchange_response({} bytes)", size);

      if (status.value() != INITIATED)
      {
        CHANNEL_RECV_FAIL("Ignoring key exchange response - not expecting it");
        return false;
      }

      // Parse fields from incoming message
      size_t peer_version = serialized::read<size_t>(data, size);
      if (peer_version != protocol_version)
      {
        CHANNEL_RECV_FAIL(
          "Protocol version mismatch (node={}, peer={})",
          protocol_version,
          peer_version);
        return false;
      }

      auto ks = extract_span(data, size);
      if (ks.empty())
      {
        CHANNEL_RECV_FAIL("Empty keyshare");
        return false;
      }

      auto sig = extract_span(data, size);
      if (sig.empty())
      {
        CHANNEL_RECV_FAIL("Empty signature");
        return false;
      }

      auto pc = extract_span(data, size);
      if (pc.empty())
      {
        CHANNEL_RECV_FAIL("Empty cert");
        return false;
      }

      if (size != 0)
      {
        CHANNEL_RECV_FAIL("{} exccess bytes remaining", size);
        return false;
      }

      // Validate cert and signature in message
      crypto::Pem cert;
      crypto::VerifierPtr verifier;
      if (!verify_peer_certificate(pc, cert, verifier))
      {
        CHANNEL_RECV_FAIL(
          "Peer certificate verification failed - recv_key_exchange_response "
          "failed to verify peer cert:\n{}\nUsing trusted service "
          "certificate:\n{}",
          cert.str(),
          service_cert.str());
        return false;
      }

      {
        // We are the initiator and expect a signature over both key shares
        std::vector<uint8_t> signed_msg(ks.begin(), ks.end());
        const auto& oks = kex_ctx.get_own_key_share();
        signed_msg.insert(signed_msg.end(), oks.begin(), oks.end());

        if (!verify_peer_signature(signed_msg, sig, verifier))
        {
          // This isn't a valid signature for this key exchange attempt.
          CHANNEL_RECV_FAIL(
            "Peer certificate verification failed - recv_key_exchange_response "
            "failed to verify signature from cert:\n{}",
            cert.str());
          return false;
        }
      }

      peer_cert = cert;
      peer_cv = verifier;

      kex_ctx.load_peer_key_share(ks);

      update_send_key();

      send_key_exchange_final();

      update_recv_key();

      establish();

      return true;
    }

    bool recv_key_exchange_final(const uint8_t* data, size_t size)
    {
      CHANNEL_RECV_TRACE("recv_key_exchange_final({} bytes)", size);

      if (status.value() != WAITING_FOR_FINAL)
      {
        CHANNEL_RECV_FAIL("Ignoring key exchange final - not expecting it");
        return false;
      }

      // Parse fields from incoming message
      // size_t peer_version = serialized::read<size_t>(data, size);
      // if (peer_version != protocol_version)
      // {
      //   CHANNEL_RECV_FAIL(
      //     "Protocol version mismatch (node={}, peer={})",
      //     protocol_version,
      //     peer_version);
      //   return false;
      // }

      auto sig = extract_span(data, size);
      if (sig.empty())
      {
        CHANNEL_RECV_FAIL("Empty signature");
        return false;
      }

      if (!verify_peer_signature(kex_ctx.get_own_key_share(), sig, peer_cv))
      {
        CHANNEL_RECV_FAIL(
          "Peer certificate verification failed - recv_key_exchange_final "
          "failed to verify signature from peer with serial number {}",
          peer_cv->serial_number());
        return false;
      }

      update_recv_key();

      establish();

      return true;
    }

  public:
    static constexpr size_t protocol_version = 1;

    Channel(
      ringbuffer::AbstractWriterFactory& writer_factory,
      const crypto::Pem& service_cert_,
      crypto::KeyPairPtr node_kp_,
      const crypto::Pem& node_cert_,
      const NodeId& self_,
      const NodeId& peer_id_,
      size_t message_limit_) :
      self(self_),
      service_cert(service_cert_),
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

    bool channel_open()
    {
      return recv_key != nullptr && send_key != nullptr;
    }

    std::span<const uint8_t> extract_span(
      const uint8_t*& data, size_t& size) const
    {
      if (size == 0)
      {
        return {};
      }

      auto sz = serialized::read<size_t>(data, size);
      const uint8_t* data_start = data;

      if (sz > size)
      {
        CHANNEL_RECV_FAIL(
          "Buffer header wants {} bytes, but only {} remain", sz, size);
        return {};
      }
      else
      {
        data += sz;
        size -= sz;
      }

      return std::span<const uint8_t>(data_start, sz);
    }

    bool verify_peer_certificate(
      std::span<const uint8_t> pc,
      crypto::Pem& cert,
      crypto::VerifierPtr& verifier)
    {
      if (!pc.empty())
      {
        cert = crypto::Pem(pc);
        verifier = crypto::make_verifier(cert);

        // 'true' is `ignore_time` => These node-to-node channels do not care
        // about certificate times, and should still pass even when given
        // expired certs
        if (!verifier->verify_certificate(
              {&service_cert}, {}, true /* no validity expiration check */))
        {
          return false;
        }

        CHANNEL_RECV_TRACE(
          "New peer certificate: {}\n{}",
          verifier->serial_number(),
          cert.str());

        return true;
      }
      else
      {
        return false;
      }
    }

    bool verify_peer_signature(
      std::span<const uint8_t> msg,
      std::span<const uint8_t> sig,
      crypto::VerifierPtr verifier)
    {
      CHANNEL_RECV_TRACE(
        "Verifying peer signature with peer certificate serial {}",
        verifier ? verifier->serial_number() : "no peer_cv!");

      if (!verifier || !verifier->verify(msg, sig))
      {
        return false;
      }

      return true;
    }

    void update_send_key()
    {
      const std::string label_to = self.value() + peer_id.value();
      const auto key_bytes = crypto::hkdf(
        crypto::MDType::SHA256,
        shared_key_size,
        kex_ctx.get_shared_secret(),
        hkdf_salt,
        {label_to.begin(), label_to.end()});
      send_key = crypto::make_key_aes_gcm(key_bytes);

      send_nonce = 1;
    }

    void update_recv_key()
    {
      const std::string label_from = peer_id.value() + self.value();
      const auto key_bytes = crypto::hkdf(
        crypto::MDType::SHA256,
        shared_key_size,
        kex_ctx.get_shared_secret(),
        hkdf_salt,
        {label_from.begin(), label_from.end()});
      recv_key = crypto::make_key_aes_gcm(key_bytes);

      local_recv_nonce = 0;
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
      status.advance(ESTABLISHED);
      LOG_INFO_FMT("Node channel with {} is now established.", peer_id);

      kex_ctx.reset();

      auto node_cv = make_verifier(node_cert);
      CHANNEL_RECV_TRACE(
        "Node certificate serial numbers: node={} peer={}",
        node_cv->serial_number(),
        peer_cv->serial_number());

      if (outgoing_consensus_msg.has_value())
      {
        send(
          outgoing_consensus_msg->type,
          outgoing_consensus_msg->raw_aad,
          outgoing_consensus_msg->raw_plain);
        outgoing_consensus_msg.reset();
      }

      for (auto& outgoing_msg : outgoing_forwarding_msgs)
      {
        send(outgoing_msg.type, outgoing_msg.raw_aad, outgoing_msg.raw_plain);
        CHANNEL_SEND_TRACE("Flushing previously queued forwarding message");
      }
      outgoing_forwarding_msgs.clear();
    }

    void initiate()
    {
      LOG_INFO_FMT("Initiating node channel with {}.", peer_id);

      // Begin with new key exchange
      kex_ctx.reset();
      peer_cert = {};
      peer_cv.reset();

      auto e = crypto::create_entropy();
      hkdf_salt = e->random(salt_len);

      // As a future simplification, we would like this to always be true
      // (initiations must travel through reset/inactive), but it is not
      // currently true
      // status.expect(INACTIVE);
      status.advance(INITIATED);

      last_initiation_time = ccf::get_enclave_time();

      send_key_exchange_init();
    }

    bool send(
      NodeMsgType type,
      std::span<const uint8_t> aad,
      std::span<const uint8_t> plain = {})
    {
      if (send_key == nullptr)
      {
        advance_connection_attempt();
        switch (type)
        {
          case (NodeMsgType::consensus_msg):
          {
            if (outgoing_consensus_msg.has_value())
            {
              LOG_DEBUG_FMT(
                "Dropping outgoing consensus message - replaced by new "
                "consensus message");
            }
            outgoing_consensus_msg = OutgoingMsg(type, aad, plain);
            return true;
          }

          case (NodeMsgType::forwarded_msg):
          {
            if (
              outgoing_forwarding_msgs.size() < outgoing_forwarding_queue_size)
            {
              outgoing_forwarding_msgs.emplace_back(type, aad, plain);
              CHANNEL_SEND_TRACE(
                "Queueing outgoing forwarding message - the is the {}/{} "
                "buffered message",
                outgoing_forwarding_msgs.size(),
                outgoing_forwarding_queue_size);
              return true;
            }
            else
            {
              CHANNEL_SEND_FAIL(
                "Unable to queue outgoing forwarding message - already queued "
                "maximum {} messages",
                outgoing_forwarding_queue_size);
              return false;
            }
          }

          default:
          {
            CHANNEL_SEND_FAIL(
              "Unhandled message type {} on unestablished channel - ignoring",
              type);
            return false;
          }
        }
      }

      auto nonce = send_nonce.fetch_add(1);
      WireNonce wire_nonce(nonce);

      CHANNEL_SEND_TRACE(
        "send({}, {} bytes, {} bytes) (nonce={})",
        (size_t)type,
        aad.size(),
        plain.size(),
        nonce);

      GcmHdr gcm_hdr;
      gcm_hdr.set_iv((const uint8_t*)&wire_nonce, sizeof(wire_nonce));

      std::vector<uint8_t> cipher;
      assert(send_key);
      send_key->encrypt(gcm_hdr.get_iv(), plain, aad, cipher, gcm_hdr.tag);

      const auto gcm_hdr_serialised = gcm_hdr.serialise();

      // Payload is concatenation of 3 things:
      // 1) aad
      // 2) gcm header
      // 3) ciphertext
      // NB: None of these are length-prefixed, so it is assumed that the
      // receiver knows the fixed size of the aad and gcm header
      const serializer::ByteRange payload[] = {
        {aad.data(), static_cast<size_t>(aad.size())},
        {gcm_hdr_serialised.data(),
         static_cast<size_t>(gcm_hdr_serialised.size())},
        {cipher.data(), static_cast<size_t>(cipher.size())}};

      RINGBUFFER_WRITE_MESSAGE(
        node_outbound, to_host, peer_id.value(), type, self.value(), payload);

      check_message_limit();

      return true;
    }

    bool recv_authenticated(
      std::span<const uint8_t> aad, const uint8_t*& data, size_t& size)
    {
      // Receive authenticated message, modifying data to point to the start of
      // the non-authenticated plaintext payload
      if (recv_key == nullptr)
      {
        LOG_INFO_FMT(
          "Node channel with {} cannot receive authenticated message: not "
          "established a receive key, status={}",
          peer_id,
          status.value());
        advance_connection_attempt();
        return false;
      }

      GcmHdr hdr;
      hdr.deserialise(data, size);

      if (!verify(hdr, aad))
      {
        CHANNEL_RECV_FAIL("Failed to verify node");
        return false;
      }

      return true;
    }

    bool recv_authenticated_with_load(const uint8_t*& data, size_t& size)
    {
      // Receive authenticated message, modifying data to point to the start of
      // the non-authenticated plaintext payload. data contains payload first,
      // then GCM header

      if (recv_key == nullptr)
      {
        LOG_INFO_FMT(
          "Node channel with {} cannot receive authenticated message with "
          "payload: not established a receive key, status={}",
          peer_id,
          status.value());
        advance_connection_attempt();
        return false;
      }

      const uint8_t* data_ = data;
      size_t size_ = size;

      GcmHdr hdr;
      serialized::skip(data_, size_, (size_ - hdr.serialised_size()));
      hdr.deserialise(data_, size_);
      size -= hdr.serialised_size();

      if (!verify(hdr, std::span<const uint8_t>(data, size)))
      {
        CHANNEL_RECV_FAIL("Failed to verify node message with payload");
        return false;
      }

      return true;
    }

    std::optional<std::vector<uint8_t>> recv_encrypted(
      std::span<const uint8_t> aad, const uint8_t*& data, size_t& size)
    {
      // Receive encrypted message, returning the decrypted payload
      if (recv_key == nullptr)
      {
        LOG_INFO_FMT(
          "Node channel with {} cannot receive encrypted message: not "
          "established a receive key, status={}",
          peer_id,
          status.value());
        advance_connection_attempt();
        return std::nullopt;
      }

      GcmHdr hdr;
      hdr.deserialise(data, size);

      std::vector<uint8_t> plain;
      if (!decrypt(hdr, aad, std::span<const uint8_t>(data, size), plain))
      {
        CHANNEL_RECV_FAIL("Failed to decrypt node message");
        return std::nullopt;
      }

      return plain;
    }

    void close_channel()
    {
      RINGBUFFER_WRITE_MESSAGE(close_node_outbound, to_host, peer_id.value());
      reset_key_exchange();
      outgoing_consensus_msg.reset();

      recv_key.reset();
      send_key.reset();
    }

    void reset_key_exchange()
    {
      LOG_INFO_FMT("Resetting channel with {}", peer_id);

      status.advance(INACTIVE);
      kex_ctx.reset();
      peer_cert = {};
      peer_cv.reset();

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

#undef CHANNEL_RECV_TRACE
#undef CHANNEL_SEND_TRACE
#undef CHANNEL_RECV_FAIL

#pragma clang diagnostic pop

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/openssl/openssl_wrappers.h"
#include "ccf/crypto/sha256_hash.h"
#include "ccf/entity_id.h"
#include "ds/internal_logger.h"

#include <array>
#include <deque>
#include <functional>

namespace asynchost
{
  // Below the RFC 8446 section 5.5 bound of 2^24.5 full-size records.
  static constexpr size_t max_node_tls_records_per_key = 1 << 24;

  struct NodeTLSCredentials
  {
    ccf::crypto::Pem service;
    ccf::crypto::Pem certificate;
    ccf::crypto::Pem private_key;
  };

  class NodeTLSContext
  {
  public:
    ccf::crypto::OpenSSL::Unique_SSL_CTX ctx{TLS_method()};

    explicit NodeTLSContext(const NodeTLSCredentials& credentials)
    {
      using namespace ccf::crypto::OpenSSL;
      CHECK1(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION));
      CHECK1(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION));
      SSL_CTX_set_verify(
        ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
      SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
      CHECK1(SSL_CTX_set_num_tickets(ctx, 0));
      Unique_BIO root_bio(credentials.service);
      Unique_X509 root(root_bio, true, true);
      CHECK1(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), root));
      // Match existing node channels: node certificates intentionally remain
      // usable after expiry. All other chain and identity checks still apply.
      CHECK1(X509_VERIFY_PARAM_set_flags(
        SSL_CTX_get0_param(ctx), X509_V_FLAG_NO_CHECK_TIME));
      Unique_BIO cert_bio(credentials.certificate);
      Unique_X509 cert(cert_bio, true, true);
      CHECK1(SSL_CTX_use_certificate(ctx, cert));
      Unique_BIO key_bio(credentials.private_key);
      Unique_SSL_OBJECT<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free> key(
        PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr),
        EVP_PKEY_free);
      CHECK1(SSL_CTX_use_PrivateKey(ctx, key));
      CHECK1(SSL_CTX_check_private_key(ctx));
    }
  };

  // The loop thread owns every SSL operation. TLS encrypts the complete
  // transport frame, including ledger entries appended by the ledger lane.
  class NodeTLSSession
  {
    std::shared_ptr<NodeTLSContext> context;
    ccf::crypto::OpenSSL::Unique_SSL ssl;
    std::optional<ccf::NodeId> expected_peer;
    std::optional<ccf::NodeId> authenticated_peer;
    std::deque<std::vector<uint8_t>> queued;
    size_t queued_bytes = 0;
    size_t frame_offset = 0;
    size_t limit;
    size_t record_limit;
    size_t sent_records = 0;
    size_t received_records = 0;
    size_t sent_updates = 0;
    bool record_limit_exceeded = false;
    bool retry_write = false;
    bool failed = false;

    static void message_callback(
      int writing,
      int,
      int content_type,
      const void* data,
      size_t size,
      SSL*,
      void* arg)
    {
      auto& session = *static_cast<NodeTLSSession*>(arg);
      if (!session.authenticated_peer.has_value() || size == 0)
      {
        return;
      }
      const auto first = *static_cast<const uint8_t*>(data);
      auto& records = writing ? session.sent_records : session.received_records;
      if (content_type == SSL3_RT_HEADER && first == SSL3_RT_APPLICATION_DATA)
      {
        // TLS 1.3 encrypts both application data and post-handshake messages
        // with this outer record type. Count records, not transport frames.
        if (++records > session.record_limit)
        {
          session.record_limit_exceeded = true;
        }
      }
      else if (content_type == SSL3_RT_HANDSHAKE && first == SSL3_MT_KEY_UPDATE)
      {
        // OpenSSL reports incoming handshake messages after decryption, and
        // outgoing messages before their enclosing record. The latter leaves
        // the update record conservatively charged to the new key as well.
        records = 0;
        if (writing)
        {
          ++session.sent_updates;
        }
      }
    }

    void check_record_limit() const
    {
      if (record_limit_exceeded)
      {
        throw std::runtime_error("Node TLS per-key record budget exceeded");
      }
    }

    void check_result(int result)
    {
      const auto error = SSL_get_error(ssl, result);
      if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
      {
        throw std::runtime_error(fmt::format(
          "Node TLS failure: {}", ccf::crypto::OpenSSL::first_error()));
      }
    }

    void authenticate()
    {
      using namespace ccf::crypto::OpenSSL;
      Unique_X509 cert(SSL_get1_peer_certificate(ssl), true);
      if (SSL_get_verify_result(ssl) != X509_V_OK)
      {
        throw std::runtime_error("Node TLS certificate verification failed");
      }
      auto* key = X509_get0_pubkey(cert);
      CHECKNULL(key);
      const auto len = i2d_PUBKEY(key, nullptr);
      CHECKPOSITIVE(len);
      std::vector<uint8_t> der(len);
      auto* p = der.data();
      CHECKEQUAL(len, i2d_PUBKEY(key, &p));
      ccf::NodeId peer = ccf::crypto::Sha256Hash(der).hex_str();
      if (expected_peer.has_value() && peer != expected_peer.value())
      {
        throw std::runtime_error("Node TLS peer identity mismatch");
      }
      authenticated_peer = peer;
    }

  public:
    using Write = std::function<bool(size_t, const uint8_t*)>;
    using Read = std::function<bool(size_t, const uint8_t*)>;

    NodeTLSSession(NodeTLSSession&&) = delete;
    NodeTLSSession& operator=(NodeTLSSession&&) = delete;

    NodeTLSSession(
      std::shared_ptr<NodeTLSContext> context_,
      std::optional<ccf::NodeId> peer,
      size_t limit_,
      size_t record_limit_ = max_node_tls_records_per_key) :
      context(std::move(context_)),
      ssl(context->ctx),
      expected_peer(std::move(peer)),
      limit(limit_),
      record_limit(record_limit_)
    {
      using namespace ccf::crypto::OpenSSL;
      if (record_limit < 4 || record_limit > max_node_tls_records_per_key)
      {
        throw std::logic_error("Node TLS record limit must be in [4, 2^24]");
      }
      CHECK1(SSL_set_max_send_fragment(ssl, 16384));
      SSL_set_msg_callback(ssl, message_callback);
      SSL_set_msg_callback_arg(ssl, this);
      Unique_BIO input;
      Unique_BIO output;
      SSL_set_bio(ssl, input.release(), output.release());
      if (expected_peer.has_value())
      {
        SSL_set_connect_state(ssl);
      }
      else
      {
        SSL_set_accept_state(ssl);
      }
    }

    const std::optional<ccf::NodeId>& peer() const
    {
      return authenticated_peer;
    }

    size_t key_updates_sent() const
    {
      return sent_updates;
    }

    void enqueue(const std::vector<uint8_t>& frame)
    {
      if (frame.size() > limit - queued_bytes)
      {
        throw std::runtime_error("Node TLS pending send limit exceeded");
      }
      queued.push_back(frame);
      queued_bytes += frame.size();
    }

    bool pump(
      std::span<const uint8_t> input, const Write& write, const Read& read)
    {
      using namespace ccf::crypto::OpenSSL;
      if (failed)
      {
        return false;
      }
      try
      {
        // Libuv delivers bounded chunks; reject oversized test/caller input
        // before handing it to the memory BIO.
        if (
          input.size() > limit ||
          BIO_ctrl_pending(SSL_get_rbio(ssl)) > limit - input.size())
        {
          throw std::runtime_error("Node TLS input limit exceeded");
        }
        if (!input.empty())
        {
          CHECKEQUAL(
            input.size(),
            BIO_write(SSL_get_rbio(ssl), input.data(), input.size()));
        }
        std::array<uint8_t, 16384> buffer;
        const auto drain = [&]() {
          auto* bio = SSL_get_wbio(ssl);
          while (BIO_ctrl_pending(bio) != 0)
          {
            const auto n = BIO_read(bio, buffer.data(), buffer.size());
            CHECKPOSITIVE(n);
            if (!write(n, buffer.data()))
            {
              throw std::runtime_error("Node TLS socket write failed");
            }
          }
        };
        if (!authenticated_peer.has_value())
        {
          ERR_clear_error();
          const auto result = SSL_do_handshake(ssl);
          if (result != 1)
          {
            check_result(result);
          }
          else
          {
            authenticate();
          }
          drain();
        }
        if (!authenticated_peer.has_value())
        {
          return true;
        }
        while (!queued.empty())
        {
          if (!retry_write && sent_records >= record_limit - 1)
          {
            // Reserve one old-key record for KeyUpdate itself. A successful
            // write below produces at most one application-data record.
            CHECK1(SSL_key_update(ssl, SSL_KEY_UPDATE_NOT_REQUESTED));
            ERR_clear_error();
            const auto result = SSL_do_handshake(ssl);
            if (result != 1)
            {
              check_result(result);
              drain();
              break;
            }
            check_record_limit();
            drain();
          }
          const auto& frame = queued.front();
          const auto count =
            std::min<size_t>(16384, frame.size() - frame_offset);
          size_t written = 0;
          ERR_clear_error();
          const auto result =
            SSL_write_ex(ssl, frame.data() + frame_offset, count, &written);
          if (result != 1)
          {
            check_result(result);
            check_record_limit();
            retry_write = true;
            drain();
            break;
          }
          // Partial-write mode is deliberately disabled: a successful write
          // consumes this record-sized chunk; WANT_* retains its exact buffer.
          CHECKEQUAL(count, written);
          check_record_limit();
          retry_write = false;
          frame_offset += written;
          queued_bytes -= written;
          if (frame_offset == frame.size())
          {
            queued.pop_front();
            frame_offset = 0;
          }
          drain();
        }
        while (true)
        {
          size_t n = 0;
          ERR_clear_error();
          const auto result =
            SSL_read_ex(ssl, buffer.data(), buffer.size(), &n);
          if (result != 1)
          {
            check_result(result);
            check_record_limit();
            drain();
            break;
          }
          check_record_limit();
          if (!read(n, buffer.data()))
          {
            throw std::runtime_error("Node TLS frame rejected");
          }
        }
        return true;
      }
      catch (const std::exception& e)
      {
        LOG_DEBUG_FMT("Closing node TLS connection: {}", e.what());
        failed = true;
        return false;
      }
    }
  };
}

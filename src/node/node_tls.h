// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/service/tables/nodes.h"
#include "ds/serialized.h"
#include "node/node_transport.h"
#include "tls/openssl_client.h"
#include "tls/openssl_server.h"

#include <charconv>
#include <functional>
#include <map>
#include <mutex>

namespace ccf
{
  // TLS owns connection security only. Consensus retries replication; forwarded
  // calls time out at their origin. No application frame is replayed on close.
  class NodeTLS
  {
    static constexpr std::string_view CONSENSUS_ALPN = "ccf-consensus/1";
    static constexpr std::string_view FORWARDING_ALPN = "ccf-forwarding/1";
    static constexpr size_t FORWARDING_QUEUE_SIZE = 10;

    struct Connection
    {
      bool outgoing = false;
      std::optional<NodeId> peer;
      NodeMsgType purpose = consensus_msg;
      std::vector<uint8_t> pending;
      std::vector<std::function<void(::tcp::ConnID)>> pending_sends;
      bool authenticated = false;
      bool rejected = false;
    };

    std::mutex mutex;
    std::atomic<::tcp::ConnID> next_id = 1;
    std::map<::tcp::ConnID, Connection> connections;
    std::map<std::pair<NodeId, NodeMsgType>, ::tcp::ConnID> outgoing;
    std::shared_ptr<NodeInboundHandler> handler;
    std::optional<crypto::Pem> service_cert;
    std::optional<crypto::Pem> node_cert;
    crypto::ECKeyPairPtr key;
    std::unique_ptr<tls::OpenSSLServer> server;
    std::shared_ptr<tls::OpenSSLClient> client;
    const size_t max_frame_size;
    const std::optional<std::chrono::milliseconds> tcp_timeout;
    const std::string source_host;

    static std::string_view alpn(NodeMsgType purpose)
    {
      return purpose == forwarded_msg ? FORWARDING_ALPN : CONSENSUS_ALPN;
    }

    static int select_alpn(
      SSL* /*ssl*/,
      const unsigned char** out,
      unsigned char* outlen,
      const unsigned char* in,
      unsigned int inlen,
      void* /*arg*/)
    {
      for (size_t offset = 0; offset < inlen;)
      {
        const auto size = in[offset++];
        if (size > inlen - offset)
        {
          break;
        }
        const std::string_view offered(
          reinterpret_cast<const char*>(in + offset), size);
        if (offered == CONSENSUS_ALPN || offered == FORWARDING_ALPN)
        {
          *out = in + offset;
          *outlen = size;
          return SSL_TLSEXT_ERR_OK;
        }
        offset += size;
      }
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    std::shared_ptr<SSL_CTX> make_context(
      const std::string& cert, const std::string& private_key, bool incoming)
    {
      if (!service_cert.has_value())
      {
        throw std::logic_error(
          "Cannot create N2N TLS context without service certificate");
      }
      namespace O = crypto::OpenSSL;
      using O::CHECK1;
      O::Unique_SSL_CTX ctx(
        incoming ? TLS_server_method() : TLS_client_method());
      CHECK1(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION));
      CHECK1(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION));
      CHECK1(SSL_CTX_set_ciphersuites(
        ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"));
      CHECK1(SSL_CTX_set1_groups_list(
        ctx,
        "?SecP384r1MLKEM1024:?SecP256r1MLKEM768:?X25519MLKEM768:"
        "P-521:P-384:P-256"));
      SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
      SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
      CHECK1(SSL_CTX_set_num_tickets(ctx, 0));
      CHECK1(SSL_CTX_set_max_early_data(ctx, 0));
      SSL_CTX_set_mode(
        ctx,
        SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
      O::Unique_BIO cert_bio(cert.data(), cert.size());
      O::Unique_X509 certificate(cert_bio, true);
      O::Unique_BIO key_bio(private_key.data(), private_key.size());
      O::Unique_PKEY private_key_ptr(
        PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr),
        EVP_PKEY_free);
      CHECK1(SSL_CTX_use_certificate(ctx, certificate));
      CHECK1(SSL_CTX_use_PrivateKey(ctx, private_key_ptr));
      CHECK1(SSL_CTX_check_private_key(ctx));
      O::Unique_BIO ca_bio(*service_cert);
      O::Unique_X509 ca(ca_bio, true);
      CHECK1(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca));
      // N2N identities remain valid after certificate expiry, as for legacy.
      CHECK1(X509_VERIFY_PARAM_set_flags(
        SSL_CTX_get0_param(ctx), X509_V_FLAG_NO_CHECK_TIME));
      SSL_CTX_set_verify(
        ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
      if (incoming)
      {
        SSL_CTX_set_alpn_select_cb(ctx, select_alpn, nullptr);
      }
      return {ctx.release(), SSL_CTX_free};
    }

    bool handshake(::tcp::ConnID id, SSL* ssl, bool is_outgoing)
    {
      std::lock_guard guard(mutex);
      if (!is_outgoing)
      {
        connections.try_emplace(id);
      }
      const auto it = connections.find(id);
      if (
        it == connections.end() || it->second.rejected ||
        SSL_get_verify_result(ssl) != X509_V_OK)
      {
        return false;
      }
      auto& connection = it->second;
      crypto::OpenSSL::Unique_X509 cert(SSL_get1_peer_certificate(ssl), false);
      if (cert == nullptr)
      {
        return false;
      }
      const int length = i2d_X509(cert, nullptr);
      if (length <= 0)
      {
        LOG_FAIL_FMT("N2N TLS {}: invalid peer certificate", id);
        return false;
      }
      std::vector<uint8_t> der(length);
      auto* output = der.data();
      if (i2d_X509(cert, &output) != length)
      {
        LOG_FAIL_FMT("N2N TLS {}: cannot encode peer certificate", id);
        return false;
      }
      const auto peer = compute_node_id_from_cert_der(der);
      const unsigned char* selected = nullptr;
      unsigned int size = 0;
      SSL_get0_alpn_selected(ssl, &selected, &size);
      const std::string_view protocol(
        reinterpret_cast<const char*>(selected), size);
      if (
        (protocol != CONSENSUS_ALPN && protocol != FORWARDING_ALPN) ||
        (is_outgoing &&
         (connection.peer != peer || protocol != alpn(connection.purpose))))
      {
        LOG_FAIL_FMT("N2N TLS {}: peer identity or ALPN mismatch", id);
        return false;
      }
      connection.peer = peer;
      connection.purpose =
        protocol == FORWARDING_ALPN ? forwarded_msg : consensus_msg;
      if (!is_outgoing)
      {
        for (auto& [other_id, other] : connections)
        {
          if (
            other_id != id && !other.outgoing && other.authenticated &&
            other.peer == peer && other.purpose == connection.purpose)
          {
            // A peer repairing a failed link replaces its previous stream.
            close_connection(other_id, other);
          }
        }
      }
      connection.authenticated = true;
      for (auto& send : connection.pending_sends)
      {
        send(id);
      }
      connection.pending_sends.clear();
      LOG_INFO_FMT("N2N TLS {} authenticated {} ({})", id, peer, protocol);
      return true;
    }

    void close_connection(::tcp::ConnID id, Connection& connection)
    {
      connection.rejected = true;
      connection.pending_sends.clear();
      if (connection.outgoing)
      {
        client->close_connection(id);
      }
      else
      {
        server->close_connection(id);
      }
    }

    void receive(::tcp::ConnID id, std::vector<uint8_t> bytes)
    {
      std::lock_guard guard(mutex);
      auto it = connections.find(id);
      if (it == connections.end() || it->second.rejected)
      {
        return;
      }
      auto& connection = it->second;
      if (!connection.authenticated)
      {
        LOG_FAIL_FMT("N2N TLS {}: application bytes before authentication", id);
        close_connection(id, connection);
        return;
      }
      connection.pending.insert(
        connection.pending.end(), bytes.begin(), bytes.end());
      size_t consumed = 0;
      try
      {
        while (connection.pending.size() - consumed >= sizeof(uint32_t))
        {
          const uint8_t* data = connection.pending.data() + consumed;
          size_t size = connection.pending.size() - consumed;
          const auto frame_size = serialized::read<uint32_t>(data, size);
          if (frame_size > max_frame_size)
          {
            throw std::logic_error("N2N TLS frame exceeds configured limit");
          }
          if (size < frame_size)
          {
            break;
          }
          size = frame_size;
          const auto purpose = serialized::read<NodeMsgType>(data, size);
          const NodeId from(serialized::read<NodeId::Value>(data, size));
          if (purpose != connection.purpose || from != connection.peer)
          {
            throw std::logic_error(
              "N2N TLS frame identity or purpose mismatch");
          }
          if (handler != nullptr)
          {
            handler->recv_node_tls_inbound(
              purpose, from, std::vector<uint8_t>(data, data + size));
          }
          consumed += sizeof(uint32_t) + frame_size;
        }
      }
      catch (const std::exception& e)
      {
        LOG_FAIL_FMT("N2N TLS {}: rejecting frame: {}", id, e.what());
        close_connection(id, connection);
      }
      connection.pending.erase(
        connection.pending.begin(), connection.pending.begin() + consumed);
    }

    void closed(::tcp::ConnID id)
    {
      std::lock_guard guard(mutex);
      const auto it = connections.find(id);
      if (it == connections.end())
      {
        return;
      }
      const auto& connection = it->second;
      if (connection.outgoing && connection.peer.has_value())
      {
        const auto stream =
          std::make_pair(*connection.peer, connection.purpose);
        auto current = outgoing.find(stream);
        if (current != outgoing.end() && current->second == id)
        {
          outgoing.erase(current);
        }
      }
      LOG_DEBUG_FMT("N2N TLS {} closed; discarding outstanding output", id);
      connections.erase(it);
    }

  public:
    NodeTLS(
      const std::string& host,
      uint16_t port,
      size_t max_frame_size_,
      std::chrono::milliseconds idle_timeout,
      std::optional<std::chrono::milliseconds> tcp_timeout_ = std::nullopt,
      std::string source_host_ = {},
      tls::TrafficKeyPolicy key_policy = {}) :
      max_frame_size(max_frame_size_),
      tcp_timeout(tcp_timeout_),
      source_host(std::move(source_host_))
    {
      auto data = [this](
                    ::tcp::ConnID id,
                    std::vector<uint8_t> bytes,
                    const std::vector<uint8_t>&,
                    bool) { receive(id, std::move(bytes)); };
      auto close = [this](::tcp::ConnID id) { closed(id); };
      auto authenticate = [this](::tcp::ConnID id, SSL* ssl, bool is_outgoing) {
        try
        {
          return handshake(id, ssl, is_outgoing);
        }
        catch (const std::exception& e)
        {
          LOG_FAIL_FMT("N2N TLS {}: authentication failed: {}", id, e.what());
          return false;
        }
      };
      client = tls::OpenSSLClient::create(
        {.idle_timeout = idle_timeout,
         .shared_next_id = &next_id,
         .on_handshake = authenticate,
         .traffic_key_policy = key_policy},
        data,
        close);
      server = std::make_unique<tls::OpenSSLServer>(
        tls::OpenSSLServer::Config{
          .host = host,
          .port = port,
          .idle_timeout = idle_timeout,
          .shared_next_id = &next_id,
          .on_handshake = authenticate,
          .traffic_key_policy = key_policy,
          .tcp_user_timeout = tcp_timeout,
          .context_factory =
            [this](const std::string& cert, const std::string& private_key) {
              std::lock_guard guard(mutex);
              return make_context(cert, private_key, true);
            }},
        data,
        close);
      client->start();
      server->start();
    }

    ~NodeTLS()
    {
      stop();
    }

    [[nodiscard]] uint16_t port() const
    {
      return server->port();
    }

    void stop()
    {
      client->stop();
      server->stop();
    }

    void set_handler(std::shared_ptr<NodeInboundHandler> handler_)
    {
      std::lock_guard guard(mutex);
      handler = std::move(handler_);
    }

    void set_identity(
      const crypto::Pem& service,
      crypto::ECKeyPairPtr key_,
      const crypto::Pem& cert)
    {
      std::lock_guard guard(mutex);
      service_cert = service;
      key = std::move(key_);
      node_cert = cert;
      // Replaces the context used by future handshakes, not established SSLs.
      server->set_server_cert(cert.str(), key->private_key_pem().str());
    }

    void close(const NodeId& peer)
    {
      std::lock_guard guard(mutex);
      for (auto& [id, connection] : connections)
      {
        if (connection.peer == peer)
        {
          close_connection(id, connection);
        }
      }
    }

    // on_ready schedules ledger-ordered frame assembly for this stream only.
    // A failed stream discards callbacks which have not run, without replay.
    bool send(
      const NodeId& peer,
      NodeMsgType purpose,
      const std::string& address,
      std::function<void(::tcp::ConnID)> on_ready)
    {
      std::lock_guard guard(mutex);
      if (!node_cert)
      {
        LOG_DEBUG_FMT("N2N TLS: dropping send to {} before setup", peer);
        return false;
      }
      const auto stream = std::make_pair(peer, purpose);
      auto current = outgoing.find(stream);
      if (current == outgoing.end())
      {
        const auto [host, port] = split_net_address(address);
        uint16_t port_number = 0;
        const auto [end, error] =
          std::from_chars(port.data(), port.data() + port.size(), port_number);
        if (
          host.empty() || error != std::errc{} ||
          end != port.data() + port.size() || port_number == 0)
        {
          LOG_FAIL_FMT(
            "N2N TLS: invalid recorded endpoint for {}: {}", peer, address);
          return false;
        }
        auto ctx =
          make_context(node_cert->str(), key->private_key_pem().str(), false);
        const auto protocol = alpn(purpose);
        std::string wire(1, static_cast<char>(protocol.size()));
        wire += protocol;
        crypto::OpenSSL::CHECKEQUAL(
          0,
          SSL_CTX_set_alpn_protos(
            ctx.get(),
            reinterpret_cast<const unsigned char*>(wire.data()),
            wire.size()));
        const auto id = client->connect(
          {.host = host,
           .port = port_number,
           .source_host = source_host,
           .tls_context = std::move(ctx),
           .tcp_user_timeout = tcp_timeout});
        if (!id)
        {
          LOG_DEBUG_FMT("N2N TLS: dropping send to {} during shutdown", peer);
          return false;
        }
        connections.emplace(
          *id,
          Connection{
            .outgoing = true,
            .peer = peer,
            .purpose = purpose,
            .pending = {},
            .pending_sends = {}});
        current = outgoing.emplace(stream, *id).first;
      }
      auto& connection = connections.at(current->second);
      if (connection.rejected)
      {
        LOG_DEBUG_FMT("N2N TLS: dropping send to {} while closing", peer);
        return false;
      }
      if (connection.authenticated)
      {
        on_ready(current->second);
        return true;
      }

      // Match legacy channel establishment: retain the latest consensus send
      // and a small FIFO of forwarded messages, before assembling ledger data.
      if (purpose == consensus_msg)
      {
        if (!connection.pending_sends.empty())
        {
          LOG_DEBUG_FMT(
            "N2N TLS: replacing pending consensus send to {}", peer);
          connection.pending_sends.clear();
        }
      }
      else if (connection.pending_sends.size() >= FORWARDING_QUEUE_SIZE)
      {
        LOG_FAIL_FMT(
          "N2N TLS: forwarding establishment queue full for {}", peer);
        return false;
      }
      connection.pending_sends.push_back(std::move(on_ready));
      return true;
    }

    void send_frame(::tcp::ConnID id, std::vector<uint8_t>&& frame)
    {
      client->send(id, std::move(frame));
    }
  };
}

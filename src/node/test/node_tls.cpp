// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/node_tls.h"

#include "ccf/ds/x509_time_fmt.h"
#include "consensus/aft/cft_types.h"
#include "crypto/certs.h"
#include "host/node_transport_bridge.h"
#include "node/node_channel_bridge.h"
#include "tasks/task_system.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <arpa/inet.h>
#include <condition_variable>
#include <csignal>
#include <doctest/doctest.h>
#include <filesystem>
#include <future>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace std::chrono_literals;

namespace
{
  using ccf::crypto::OpenSSL::CHECK1;

  struct LoopRunner
  {
    uv_async_t stop{};
    std::thread thread;

    LoopRunner()
    {
      REQUIRE(uv_async_init(uv_default_loop(), &stop, [](uv_async_t* handle) {
                uv_stop(handle->loop);
              }) == 0);
      thread = std::thread([]() { uv_run(uv_default_loop(), UV_RUN_DEFAULT); });
    }

    ~LoopRunner()
    {
      uv_async_send(&stop);
      thread.join();
      uv_close(reinterpret_cast<uv_handle_t*>(&stop), nullptr);
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
  };

  struct Identity
  {
    ccf::crypto::ECKeyPairPtr key = ccf::crypto::make_ec_key_pair();
    ccf::crypto::Pem cert;

    ccf::NodeId id() const
    {
      return ccf::compute_node_id_from_kp(key);
    }
  };

  struct Service
  {
    ccf::crypto::ECKeyPairPtr key = ccf::crypto::make_ec_key_pair();
    ccf::crypto::Pem cert = ccf::crypto::create_self_signed_cert(
      key,
      "CN=test service",
      {},
      ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 24h),
      365);

    void endorse(Identity& identity, bool expired = false)
    {
      identity.cert = ccf::crypto::create_endorsed_cert(
        identity.key,
        "CN=test node",
        {},
        ccf::ds::to_x509_time_string(
          std::chrono::system_clock::now() - (expired ? 72h : 24h)),
        expired ? 1 : 365,
        key->private_key_pem(),
        cert);
    }
  };

  template <typename T>
  std::vector<uint8_t> bytes(const T& value)
  {
    const auto* begin = reinterpret_cast<const uint8_t*>(&value);
    return {begin, begin + sizeof(value)};
  }

  std::vector<uint8_t> consensus_payload()
  {
    aft::RequestVote vote{};
    vote.term = 3;
    vote.last_committable_idx = 42;
    vote.term_of_last_committable_idx = 2;
    return bytes(vote);
  }

  std::vector<uint8_t> forwarding_payload()
  {
    auto payload = bytes(ccf::ForwardedCommandHeader_v3{19, 3});
    const std::string request = "GET /app/log/private HTTP/1.1\r\n\r\n";
    payload.insert(payload.end(), request.begin(), request.end());
    return payload;
  }

  std::vector<uint8_t> frame(
    const ccf::NodeId& from,
    ccf::NodeMsgType purpose,
    const std::vector<uint8_t>& payload)
  {
    const auto size =
      sizeof(purpose) + sizeof(size_t) + from.size() + payload.size();
    std::vector<uint8_t> result(sizeof(uint32_t) + size);
    auto* out = result.data();
    auto remaining = result.size();
    serialized::write(out, remaining, static_cast<uint32_t>(size));
    serialized::write(out, remaining, purpose);
    serialized::write(out, remaining, from.value());
    serialized::write(out, remaining, payload.data(), payload.size());
    return result;
  }

  bool send_frame(
    ccf::NodeTLS& sender,
    const std::string& address,
    const ccf::NodeId& peer,
    ccf::NodeMsgType purpose,
    std::vector<uint8_t> framed)
  {
    return sender.send(
      peer,
      purpose,
      address,
      [&sender, framed = std::move(framed)](::tcp::ConnID id) mutable {
        sender.send_frame(id, std::move(framed));
      });
  }

  struct Receiver : ccf::NodeInboundHandler
  {
    struct Message
    {
      ccf::NodeMsgType purpose;
      ccf::NodeId from;
      std::vector<uint8_t> payload;
    };

    std::mutex mutex;
    std::condition_variable cv;
    std::vector<Message> messages;

    void recv_node_inbound(
      ccf::NodeMsgType, const ccf::NodeId&, std::vector<uint8_t>&&) override
    {
      FAIL("TLS ingress must not use legacy delivery");
    }

    void recv_node_tls_inbound(
      ccf::NodeMsgType purpose,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload) override
    {
      std::lock_guard guard(mutex);
      messages.push_back({purpose, from, std::move(payload)});
      cv.notify_all();
    }

    bool wait(size_t count, std::chrono::milliseconds timeout = 3s)
    {
      std::unique_lock lock(mutex);
      return cv.wait_for(
        lock, timeout, [&]() { return messages.size() >= count; });
    }

    std::vector<Message> snapshot()
    {
      std::lock_guard guard(mutex);
      return messages;
    }
  };

  struct Fixture
  {
    static constexpr size_t MAX_FRAME_SIZE = 4096;
    Service service;
    Identity alice;
    Identity bob;
    std::shared_ptr<Receiver> received = std::make_shared<Receiver>();
    ccf::NodeTLS node{"127.0.0.1", 0, MAX_FRAME_SIZE, 10s};

    Fixture()
    {
      service.endorse(alice);
      service.endorse(bob);
      node.set_identity(service.cert, bob.key, bob.cert);
      node.set_handler(received);
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }

    ~Fixture()
    {
      node.stop();
      uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    }
  };

  // Blocking test peer; the transport under test still uses the shared native
  // OpenSSL engine and real TCP. Socket timeouts bound negative assertions.
  struct Peer
  {
    int fd = -1;
    ccf::crypto::OpenSSL::Unique_SSL_CTX context{TLS_client_method()};
    ccf::crypto::OpenSSL::Unique_SSL ssl{context};

    Peer(
      uint16_t port,
      const Service& service,
      const Identity* identity,
      std::string_view protocol = "ccf-consensus/1",
      int version = TLS1_3_VERSION)
    {
      CHECK1(SSL_CTX_set_min_proto_version(context, version));
      CHECK1(SSL_CTX_set_max_proto_version(context, version));
      ccf::crypto::OpenSSL::Unique_BIO ca_bio(service.cert);
      ccf::crypto::OpenSSL::Unique_X509 ca(ca_bio, true);
      CHECK1(X509_STORE_add_cert(SSL_CTX_get_cert_store(context), ca));
      SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
      CHECK1(X509_VERIFY_PARAM_set_flags(
        SSL_CTX_get0_param(context), X509_V_FLAG_NO_CHECK_TIME));
      if (identity != nullptr)
      {
        ccf::crypto::OpenSSL::Unique_BIO cert_bio(identity->cert);
        ccf::crypto::OpenSSL::Unique_X509 cert(cert_bio, true);
        CHECK1(SSL_CTX_use_certificate(context, cert));
        const auto key_pem = identity->key->private_key_pem();
        ccf::crypto::OpenSSL::Unique_BIO key_bio(key_pem);
        ccf::crypto::OpenSSL::Unique_PKEY key(
          PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr),
          EVP_PKEY_free);
        CHECK1(SSL_CTX_use_PrivateKey(context, key));
      }
      if (!protocol.empty())
      {
        std::string wire(1, static_cast<char>(protocol.size()));
        wire += protocol;
        REQUIRE(
          SSL_CTX_set_alpn_protos(
            context,
            reinterpret_cast<const unsigned char*>(wire.data()),
            wire.size()) == 0);
      }
      fd = ::socket(AF_INET, SOCK_STREAM, 0);
      REQUIRE(fd >= 0);
      timeval timeout{3, 0};
      REQUIRE(
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ==
        0);
      REQUIRE(
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) ==
        0);
      sockaddr_in address{};
      address.sin_family = AF_INET;
      address.sin_port = htons(port);
      REQUIRE(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
      REQUIRE(
        ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) ==
        0);
      ssl.reset(SSL_new(context));
      CHECK1(SSL_set_fd(ssl, fd));
    }

    ~Peer()
    {
      ssl.reset(nullptr);
      if (fd >= 0)
      {
        ::close(fd);
      }
    }

    bool connect()
    {
      return SSL_connect(ssl) == 1;
    }

    void send(const std::vector<uint8_t>& data)
    {
      size_t written = 0;
      REQUIRE(SSL_write_ex(ssl, data.data(), data.size(), &written) == 1);
      REQUIRE(written == data.size());
    }

    bool closed()
    {
      uint8_t byte = 0;
      const auto result = SSL_read(ssl, &byte, 1);
      if (result > 0)
      {
        return false;
      }
      const auto error = SSL_get_error(ssl, result);
      return error == SSL_ERROR_ZERO_RETURN || error == SSL_ERROR_SSL ||
        (error == SSL_ERROR_SYSCALL && result == 0);
    }
  };

  struct RecordingTransport : ccf::AbstractNodeTransport
  {
    std::optional<ccf::NodeId> enabled;
    std::vector<Receiver::Message> tls_messages;
    size_t legacy_messages = 0;
    size_t identities = 0;
    size_t legacy_closes = 0;
    size_t tls_closes = 0;
    bool tls_send_result = true;

    void associate_node_address(
      const ccf::NodeId&, const std::string&, const std::string&) override
    {}

    void send(
      const ccf::NodeId&,
      ccf::NodeMsgType,
      const ccf::NodeId&,
      std::vector<uint8_t>&&) override
    {
      ++legacy_messages;
    }

    void close(const ccf::NodeId&) override
    {
      ++legacy_closes;
    }

    void close_tls(const ccf::NodeId&) override
    {
      ++tls_closes;
    }

    void set_inbound_handler(std::shared_ptr<ccf::NodeInboundHandler>) override
    {}

    bool uses_tls(const ccf::NodeId& peer) override
    {
      return enabled == peer;
    }

    void associate_tls_address(
      const ccf::NodeId& peer,
      const std::optional<std::string>& address) override
    {
      enabled = address ? std::optional(peer) : std::nullopt;
    }

    void set_tls_identity(
      const ccf::crypto::Pem&,
      ccf::crypto::ECKeyPairPtr,
      const ccf::crypto::Pem&) override
    {
      ++identities;
    }

    bool send_tls(
      const ccf::NodeId&,
      ccf::NodeMsgType purpose,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload) override
    {
      tls_messages.push_back({purpose, from, std::move(payload)});
      return tls_send_result;
    }
  };
}

TEST_CASE("NodeTLS accepts endorsed identities on separate purpose streams")
{
  Fixture f;
  ccf::NodeTLS sender{"127.0.0.1", 0, Fixture::MAX_FRAME_SIZE, 10s};
  sender.set_identity(f.service.cert, f.alice.key, f.alice.cert);
  const auto address = fmt::format("127.0.0.1:{}", f.node.port());
  LoopRunner loop;
  const auto consensus = consensus_payload();
  const auto forwarding = forwarding_payload();
  send_frame(
    sender,
    address,
    f.bob.id(),
    ccf::consensus_msg,
    frame(f.alice.id(), ccf::consensus_msg, consensus));
  send_frame(
    sender,
    address,
    f.bob.id(),
    ccf::forwarded_msg,
    frame(f.alice.id(), ccf::forwarded_msg, forwarding));
  REQUIRE(f.received->wait(2));
  const auto messages = f.received->snapshot();
  REQUIRE(messages.size() == 2);
  for (const auto& message : messages)
  {
    CHECK(message.from == f.alice.id());
    CHECK(
      message.payload ==
      (message.purpose == ccf::consensus_msg ? consensus : forwarding));
  }
  CHECK(messages[0].purpose != messages[1].purpose);
}

TEST_CASE("NodeTLS bounds callbacks only while establishing a purpose stream")
{
  auto purpose = ccf::consensus_msg;
  SUBCASE("consensus keeps only its latest pending callback") {}
  SUBCASE("forwarding keeps its first ten pending callbacks in order")
  {
    purpose = ccf::forwarded_msg;
  }

  Fixture f;
  ccf::NodeTLS sender{"127.0.0.1", 0, Fixture::MAX_FRAME_SIZE, 10s};
  sender.set_identity(f.service.cert, f.alice.key, f.alice.cert);
  const auto address = fmt::format("127.0.0.1:{}", f.node.port());
  std::atomic<size_t> callbacks = 0;
  std::atomic<::tcp::ConnID> stream_id = 0;
  const auto payload = [&](uint8_t sequence) {
    auto result = purpose == ccf::consensus_msg ? consensus_payload() :
                                                  forwarding_payload();
    result.push_back(sequence);
    return result;
  };
  const auto queue = [&](uint8_t sequence) {
    return sender.send(
      f.bob.id(),
      purpose,
      address,
      [&, framed = frame(f.alice.id(), purpose, payload(sequence))](
        ::tcp::ConnID id) mutable {
        const auto previous = stream_id.exchange(id);
        if (previous != 0)
        {
          CHECK(id == previous);
        }
        ++callbacks;
        sender.send_frame(id, std::move(framed));
      });
  };

  // Without running libuv, no TCP connection or TLS handshake can complete.
  for (uint8_t sequence = 0; sequence < 12; ++sequence)
  {
    CHECK(queue(sequence) == (purpose == ccf::consensus_msg || sequence < 10));
  }
  CHECK(callbacks == 0);
  CHECK(f.received->snapshot().empty());

  const size_t pending_count = purpose == ccf::consensus_msg ? 1 : 10;
  LoopRunner loop;
  REQUIRE(f.received->wait(pending_count));
  CHECK(callbacks == pending_count);
  const auto pending = f.received->snapshot();
  REQUIRE(pending.size() == pending_count);
  for (size_t i = 0; i < pending_count; ++i)
  {
    CHECK(pending[i].from == f.alice.id());
    CHECK(pending[i].purpose == purpose);
    CHECK(
      pending[i].payload == payload(purpose == ccf::consensus_msg ? 11 : i));
  }

  for (uint8_t sequence = 12; sequence < 27; ++sequence)
  {
    CHECK(queue(sequence));
    CHECK(callbacks == pending_count + sequence - 11);
  }
  REQUIRE(f.received->wait(pending_count + 15));
  CHECK_FALSE(f.received->wait(pending_count + 16, 50ms));
  const auto established = f.received->snapshot();
  REQUIRE(established.size() == pending_count + 15);
  for (size_t i = 0; i < 15; ++i)
  {
    CHECK(established[pending_count + i].from == f.alice.id());
    CHECK(established[pending_count + i].purpose == purpose);
    CHECK(established[pending_count + i].payload == payload(12 + i));
  }
}

TEST_CASE("NodeTLS discards pending callbacks on failed establishment or close")
{
  const auto check_discarded = [](ccf::NodeMsgType purpose, bool local_close) {
    Fixture f;
    Identity unexpected;
    f.service.endorse(unexpected);
    if (!local_close)
    {
      f.node.set_identity(f.service.cert, unexpected.key, unexpected.cert);
    }
    ccf::NodeTLS sender{"127.0.0.1", 0, Fixture::MAX_FRAME_SIZE, 10s};
    sender.set_identity(f.service.cert, f.alice.key, f.alice.cert);
    const auto address = fmt::format("127.0.0.1:{}", f.node.port());
    std::atomic<size_t> callbacks = 0;
    std::vector<std::future<void>> discarded;
    const size_t count = purpose == ccf::consensus_msg ? 1 : 10;
    for (size_t i = 0; i < count; ++i)
    {
      auto pending = std::make_shared<std::promise<void>>();
      discarded.push_back(pending->get_future());
      REQUIRE(sender.send(
        f.bob.id(),
        purpose,
        address,
        [&, pending, framed = frame(f.alice.id(), purpose, {0xaa})](
          ::tcp::ConnID id) mutable {
          ++callbacks;
          pending->set_value();
          sender.send_frame(id, std::move(framed));
        }));
    }
    CHECK(callbacks == 0);
    if (local_close)
    {
      sender.close(f.bob.id());
      for (auto& callback : discarded)
      {
        CHECK(callback.wait_for(0s) == std::future_status::ready);
      }
    }
    {
      LoopRunner loop;
      // A broken promise observes destruction, not just lack of delivery.
      for (auto& callback : discarded)
      {
        REQUIRE(callback.wait_for(3s) == std::future_status::ready);
        CHECK_THROWS_AS(callback.get(), std::future_error);
      }
      CHECK(callbacks == 0);
      CHECK(f.received->snapshot().empty());
    }

    f.node.set_identity(f.service.cert, f.bob.key, f.bob.cert);
    {
      LoopRunner loop;
      CHECK_FALSE(f.received->wait(1, 50ms));
      REQUIRE(send_frame(
        sender,
        address,
        f.bob.id(),
        purpose,
        frame(f.alice.id(), purpose, {0xbb})));
      REQUIRE(f.received->wait(1));
      CHECK_FALSE(f.received->wait(2, 50ms));
      const auto messages = f.received->snapshot();
      REQUIRE(messages.size() == 1);
      CHECK(messages[0].from == f.alice.id());
      CHECK(messages[0].purpose == purpose);
      CHECK(messages[0].payload == std::vector<uint8_t>{0xbb});
      CHECK(callbacks == 0);
    }
  };
  SUBCASE("consensus authentication failure")
  {
    check_discarded(ccf::consensus_msg, false);
  }
  SUBCASE("forwarding authentication failure")
  {
    check_discarded(ccf::forwarded_msg, false);
  }
  SUBCASE("consensus local close before authentication")
  {
    check_discarded(ccf::consensus_msg, true);
  }
  SUBCASE("forwarding local close before authentication")
  {
    check_discarded(ccf::forwarded_msg, true);
  }
}

TEST_CASE("NodeTLS enforces mutual authentication and strict ALPN/TLS1.3")
{
  Fixture f;
  LoopRunner loop;
  SUBCASE("trusted peer negotiates TLS1.3 and consensus ALPN")
  {
    Peer peer(f.node.port(), f.service, &f.alice);
    REQUIRE(peer.connect());
    CHECK(SSL_version(peer.ssl) == TLS1_3_VERSION);
    const unsigned char* selected = nullptr;
    unsigned int length = 0;
    SSL_get0_alpn_selected(peer.ssl, &selected, &length);
    CHECK(
      std::string_view(reinterpret_cast<const char*>(selected), length) ==
      "ccf-consensus/1");
    peer.send(frame(f.alice.id(), ccf::consensus_msg, consensus_payload()));
    REQUIRE(f.received->wait(1));
  }
  SUBCASE("no client certificate")
  {
    Peer peer(f.node.port(), f.service, nullptr);
    peer.connect();
    CHECK(peer.closed());
  }
  SUBCASE("client signed by another service")
  {
    Service unrelated;
    Identity stranger;
    unrelated.endorse(stranger);
    Peer peer(f.node.port(), f.service, &stranger);
    peer.connect();
    CHECK(peer.closed());
  }
  SUBCASE("unsupported ALPN")
  {
    Peer peer(f.node.port(), f.service, &f.alice, "h2");
    CHECK_FALSE(peer.connect());
  }
  SUBCASE("missing ALPN")
  {
    Peer peer(f.node.port(), f.service, &f.alice, "");
    peer.connect();
    CHECK(peer.closed());
  }
  SUBCASE("TLS1.2")
  {
    Peer peer(
      f.node.port(), f.service, &f.alice, "ccf-consensus/1", TLS1_2_VERSION);
    CHECK_FALSE(peer.connect());
  }
}

TEST_CASE("NodeTLS rejects invalid frames without delivering their payload")
{
  Fixture f;
  LoopRunner loop;
  Peer peer(f.node.port(), f.service, &f.alice);
  REQUIRE(peer.connect());
  std::vector<uint8_t> invalid;
  SUBCASE("oversize length without body")
  {
    invalid = bytes(uint32_t{Fixture::MAX_FRAME_SIZE + 1});
  }
  SUBCASE("zero length")
  {
    invalid = bytes(uint32_t{0});
  }
  SUBCASE("truncated message type")
  {
    invalid = bytes(uint32_t{1});
    invalid.push_back(0);
  }
  SUBCASE("truncated sender")
  {
    invalid = bytes(uint32_t{sizeof(ccf::NodeMsgType)});
    const auto purpose = bytes(ccf::consensus_msg);
    invalid.insert(invalid.end(), purpose.begin(), purpose.end());
  }
  SUBCASE("claimed identity differs from authenticated key")
  {
    invalid = frame(f.bob.id(), ccf::consensus_msg, consensus_payload());
  }
  SUBCASE("purpose differs from ALPN")
  {
    invalid = frame(f.alice.id(), ccf::forwarded_msg, forwarding_payload());
  }
  peer.send(invalid);
  CHECK(peer.closed());
  CHECK(f.received->snapshot().empty());
  Peer replacement(f.node.port(), f.service, &f.alice);
  REQUIRE(replacement.connect());
  replacement.send(
    frame(f.alice.id(), ccf::consensus_msg, consensus_payload()));
  REQUIRE(f.received->wait(1));
}

TEST_CASE("NodeTLS buffers fragmented frames and splits coalesced frames")
{
  Fixture f;
  LoopRunner loop;
  Peer peer(f.node.port(), f.service, &f.alice);
  REQUIRE(peer.connect());
  const auto first =
    frame(f.alice.id(), ccf::consensus_msg, consensus_payload());
  peer.send({first.begin(), first.begin() + 2});
  CHECK_FALSE(f.received->wait(1, 50ms));
  std::vector<uint8_t> rest(first.begin() + 2, first.end());
  rest.insert(rest.end(), first.begin(), first.end());
  peer.send(rest);
  REQUIRE(f.received->wait(2));
  for (const auto& message : f.received->snapshot())
  {
    CHECK(message.from == f.alice.id());
    CHECK(message.payload == consensus_payload());
  }
}

TEST_CASE("NodeTLS authenticates the expected outgoing peer identity")
{
  Fixture f;
  ccf::NodeTLS sender{"127.0.0.1", 0, Fixture::MAX_FRAME_SIZE, 10s};
  sender.set_identity(f.service.cert, f.alice.key, f.alice.cert);
  const ccf::NodeId wrong_peer{std::string(64, '0')};
  const auto address = fmt::format("127.0.0.1:{}", f.node.port());
  LoopRunner loop;
  send_frame(
    sender,
    address,
    wrong_peer,
    ccf::consensus_msg,
    frame(f.alice.id(), ccf::consensus_msg, consensus_payload()));
  CHECK_FALSE(f.received->wait(1, 150ms));
  send_frame(
    sender,
    address,
    f.bob.id(),
    ccf::consensus_msg,
    frame(f.alice.id(), ccf::consensus_msg, consensus_payload()));
  REQUIRE(f.received->wait(1));
  CHECK_FALSE(f.received->wait(2, 50ms));
}

TEST_CASE("NodeTLS accepts expired endorsements and preserves renewed streams")
{
  Fixture f;
  f.service.endorse(f.alice, true);
  f.service.endorse(f.bob, true);
  f.node.set_identity(f.service.cert, f.bob.key, f.bob.cert);
  LoopRunner loop;
  Peer peer(f.node.port(), f.service, &f.alice);
  REQUIRE(peer.connect());
  const auto message =
    frame(f.alice.id(), ccf::consensus_msg, consensus_payload());
  peer.send(message);
  REQUIRE(f.received->wait(1));
  const auto old_id = f.bob.id();
  const auto old_cert = f.bob.cert;
  f.service.endorse(f.bob);
  REQUIRE(f.bob.cert != old_cert);
  REQUIRE(f.bob.id() == old_id);
  f.node.set_identity(f.service.cert, f.bob.key, f.bob.cert);
  peer.send(message);
  REQUIRE(f.received->wait(2));
  f.node.close(f.alice.id());
  CHECK(peer.closed());
  Peer replacement(f.node.port(), f.service, &f.alice);
  REQUIRE(replacement.connect());
  CHECK_FALSE(f.received->wait(3, 50ms));
  replacement.send(message);
  REQUIRE(f.received->wait(3));
}

TEST_CASE("NodeTLS replaces only the incoming stream with the same purpose")
{
  Fixture f;
  LoopRunner loop;
  Peer old(f.node.port(), f.service, &f.alice);
  REQUIRE(old.connect());
  const auto consensus =
    frame(f.alice.id(), ccf::consensus_msg, consensus_payload());
  old.send(consensus);
  REQUIRE(f.received->wait(1));
  Peer forwarding(f.node.port(), f.service, &f.alice, "ccf-forwarding/1");
  REQUIRE(forwarding.connect());
  const auto forwarded =
    frame(f.alice.id(), ccf::forwarded_msg, forwarding_payload());
  forwarding.send(forwarded);
  REQUIRE(f.received->wait(2));
  Peer replacement(f.node.port(), f.service, &f.alice);
  REQUIRE(replacement.connect());
  replacement.send(consensus);
  REQUIRE(f.received->wait(3));
  CHECK(old.closed());
  forwarding.send(forwarded);
  REQUIRE(f.received->wait(4));
  const auto messages = f.received->snapshot();
  REQUIRE(messages.size() == 4);
  CHECK(messages[0].purpose == ccf::consensus_msg);
  CHECK(messages[1].purpose == ccf::forwarded_msg);
  CHECK(messages[2].purpose == ccf::consensus_msg);
  CHECK(messages[3].purpose == ccf::forwarded_msg);
}

TEST_CASE("NodeTLS closes outgoing streams without replaying queued frames")
{
  uint64_t record_budget = 2;
  bool remote_close = false;
  SUBCASE("budget 2 and local close") {}
  SUBCASE("budget 3 and remote close")
  {
    record_budget = 3;
    remote_close = true;
  }
  Fixture f;
  std::mutex mutex;
  std::condition_variable cv;
  std::vector<uint8_t> received;
  std::atomic<size_t> key_updates = 0;
  ::tcp::ConnID incoming_id = 0;
  size_t handshakes = 0;
  size_t closes = 0;
  ccf::tls::OpenSSLServer observer(
    {.host = "127.0.0.1",
     .cert_pem = f.bob.cert.str(),
     .key_pem = f.bob.key->private_key_pem().str(),
     .alpn = "ccf-consensus/1",
     .on_handshake =
       [&](::tcp::ConnID id, SSL* ssl, bool outgoing) {
         CHECK_FALSE(outgoing);
         CHECK(SSL_version(ssl) == TLS1_3_VERSION);
         SSL_set_msg_callback_arg(ssl, &key_updates);
         SSL_set_msg_callback(
           ssl,
           [](
             int writing,
             int,
             int type,
             const void* data,
             size_t size,
             SSL*,
             void* argument) {
             if (
               writing == 0 && type == SSL3_RT_HANDSHAKE && size == 5 &&
               *static_cast<const uint8_t*>(data) == SSL3_MT_KEY_UPDATE)
             {
               ++*static_cast<std::atomic<size_t>*>(argument);
             }
           });
         std::lock_guard guard(mutex);
         incoming_id = id;
         ++handshakes;
         cv.notify_all();
         return true;
       }},
    [&](
      ::tcp::ConnID,
      std::vector<uint8_t> data,
      const std::vector<uint8_t>& peer_cert,
      bool) {
      CHECK(ccf::compute_node_id_from_cert_der(peer_cert) == f.alice.id());
      std::lock_guard guard(mutex);
      received.insert(received.end(), data.begin(), data.end());
      cv.notify_all();
    },
    [&](::tcp::ConnID) {
      std::lock_guard guard(mutex);
      ++closes;
      cv.notify_all();
    });
  observer.start();
  ccf::NodeTLS sender{
    "127.0.0.1",
    0,
    Fixture::MAX_FRAME_SIZE,
    10s,
    std::nullopt,
    {},
    {.record_budget = record_budget}};
  sender.set_identity(f.service.cert, f.alice.key, f.alice.cert);
  const auto address = fmt::format("127.0.0.1:{}", observer.port());
  std::vector<uint8_t> initial;
  ::tcp::ConnID old_outgoing_id = 0;
  {
    LoopRunner loop;
    for (uint8_t sequence = 0; sequence < 8; ++sequence)
    {
      auto payload = consensus_payload();
      payload.push_back(sequence);
      const auto message = frame(f.alice.id(), ccf::consensus_msg, payload);
      initial.insert(initial.end(), message.begin(), message.end());
      send_frame(sender, address, f.bob.id(), ccf::consensus_msg, message);
      std::unique_lock lock(mutex);
      REQUIRE(cv.wait_for(
        lock, 3s, [&]() { return received.size() == initial.size(); }));
      REQUIRE(handshakes == 1);
      REQUIRE(received == initial);
    }
    CHECK(key_updates >= 3);
    REQUIRE(sender.send(
      f.bob.id(), ccf::consensus_msg, address, [&](::tcp::ConnID id) {
        old_outgoing_id = id;
      }));
    REQUIRE(old_outgoing_id != 0);
  }
  // With the loop paused, this frame is certainly queued rather than written.
  // FIFO processing may still deliver it before applying close, but must never
  // replay it on a replacement stream.
  auto abandoned_payload = consensus_payload();
  abandoned_payload.push_back(0xaa);
  const auto abandoned =
    frame(f.alice.id(), ccf::consensus_msg, abandoned_payload);
  send_frame(sender, address, f.bob.id(), ccf::consensus_msg, abandoned);
  if (remote_close)
  {
    observer.close_connection(incoming_id);
  }
  else
  {
    sender.close(f.bob.id());
  }
  {
    LoopRunner loop;
    std::vector<uint8_t> before_reconnect;
    {
      std::unique_lock lock(mutex);
      REQUIRE(cv.wait_for(lock, 3s, [&]() { return closes == 1; }));
      auto with_abandoned = initial;
      with_abandoned.insert(
        with_abandoned.end(), abandoned.begin(), abandoned.end());
      REQUIRE((received == initial || received == with_abandoned));
      before_reconnect = received;
      CHECK_FALSE(cv.wait_for(lock, 150ms, [&]() {
        return handshakes != 1 || received != before_reconnect;
      }));
    }
    auto next_payload = consensus_payload();
    next_payload.push_back(0xbb);
    const auto next = frame(f.alice.id(), ccf::consensus_msg, next_payload);
    send_frame(sender, address, f.bob.id(), ccf::consensus_msg, next);
    std::unique_lock lock(mutex);
    REQUIRE(cv.wait_for(lock, 3s, [&]() {
      return received.size() >= before_reconnect.size() + next.size();
    }));
    auto expected = before_reconnect;
    expected.insert(expected.end(), next.begin(), next.end());
    CHECK(received == expected);
    CHECK(handshakes == 2);
    lock.unlock();
    // Ledger-ordered assembly can finish after its original stream is gone.
    sender.send_frame(
      old_outgoing_id, frame(f.alice.id(), ccf::consensus_msg, {0xcc}));
    lock.lock();
    CHECK_FALSE(cv.wait_for(
      lock, 150ms, [&]() { return received != expected || handshakes != 2; }));
  }
}

TEST_CASE("NodeTransportBridge retains peer registration across reconnects")
{
  auto tls = std::make_shared<ccf::NodeTLS>(
    "127.0.0.1", 0, Fixture::MAX_FRAME_SIZE, 10s);
  const auto directory = std::filesystem::temp_directory_path() /
    fmt::format("node_transport_bridge_{}_{}", getpid(), tls->port());

  struct Cleanup
  {
    std::filesystem::path directory;

    ~Cleanup()
    {
      std::filesystem::remove_all(directory);
    }
  } cleanup{directory};

  asynchost::Ledger ledger(directory.string());
  ccf::tasks::JobBoard job_board;
  asynchost::LedgerSubsystem subsystem(ledger, 1024, job_board);
  const ccf::NodeId tls_peer{std::string(64, '1')};
  const ccf::NodeId legacy_peer{std::string(64, '2')};
  SUBCASE("local TLS is disabled")
  {
    asynchost::NodeTransportBridge bridge(ledger, subsystem, nullptr, nullptr);
    bridge.associate_tls_address(tls_peer, "127.0.0.1:8082");
    CHECK_FALSE(bridge.uses_tls(tls_peer));
  }
  SUBCASE("registered choices cannot change")
  {
    asynchost::NodeTransportBridge bridge(ledger, subsystem, nullptr, tls);
    bridge.associate_tls_address(tls_peer, "127.0.0.1:8082");
    bridge.associate_tls_address(tls_peer, "127.0.0.1:8082");
    CHECK(bridge.uses_tls(tls_peer));
    bridge.close_tls(tls_peer);
    CHECK(bridge.uses_tls(tls_peer));
    CHECK_THROWS_AS(
      bridge.associate_tls_address(tls_peer, std::nullopt), std::logic_error);
    CHECK_THROWS_AS(
      bridge.associate_tls_address(tls_peer, "127.0.0.1:9999"),
      std::logic_error);
    CHECK(bridge.uses_tls(tls_peer));
    bridge.associate_tls_address(legacy_peer, std::nullopt);
    bridge.associate_tls_address(legacy_peer, std::nullopt);
    CHECK_FALSE(bridge.uses_tls(legacy_peer));
    CHECK_THROWS_AS(
      bridge.associate_tls_address(legacy_peer, "127.0.0.1:8082"),
      std::logic_error);
    CHECK_FALSE(bridge.uses_tls(legacy_peer));
  }
  SUBCASE("lookup misses do not register a peer")
  {
    asynchost::NodeTransportBridge bridge(ledger, subsystem, nullptr, tls);
    CHECK_FALSE(bridge.uses_tls(tls_peer));
    bridge.associate_tls_address(tls_peer, "127.0.0.1:8082");
    CHECK(bridge.uses_tls(tls_peer));
    CHECK_FALSE(bridge.uses_tls(legacy_peer));
    bridge.associate_tls_address(legacy_peer, std::nullopt);
    CHECK_THROWS_AS(
      bridge.associate_tls_address(legacy_peer, "127.0.0.1:8082"),
      std::logic_error);
  }
  tls->stop();
  uv_run(uv_default_loop(), UV_RUN_NOWAIT);
}

TEST_CASE("NodeChannelBridge selects TLS only from recorded metadata")
{
  Service service;
  Identity alice;
  Identity bob;
  service.endorse(alice);
  service.endorse(bob);
  auto transport = std::make_shared<RecordingTransport>();
  ccf::NodeChannelBridge channels(transport);
  channels.set_message_limit(1000);
  channels.initialize(alice.id(), service.cert, alice.key, alice.cert);
  REQUIRE(transport->identities == 1);
  const auto consensus = consensus_payload();
  const ccf::NodeId legacy_peer{std::string(64, '0')};
  channels.send_authenticated(
    legacy_peer, ccf::consensus_msg, consensus.data(), consensus.size());
  REQUIRE(transport->legacy_messages > 0);
  const auto legacy_count = transport->legacy_messages;
  channels.associate_node_tls_address(bob.id(), "127.0.0.1:1");
  CHECK(channels.send_authenticated(
    bob.id(), ccf::consensus_msg, consensus.data(), consensus.size()));
  const auto forwarding = forwarding_payload();
  const std::vector<uint8_t> body{1, 2, 3};
  CHECK(
    channels.send_encrypted(bob.id(), ccf::forwarded_msg, forwarding, body));
  REQUIRE(transport->tls_messages.size() == 2);
  CHECK(transport->tls_messages[0].from == alice.id());
  CHECK(transport->tls_messages[0].purpose == ccf::consensus_msg);
  CHECK(transport->tls_messages[0].payload == consensus);
  auto expected = forwarding;
  expected.insert(expected.end(), body.begin(), body.end());
  CHECK(transport->tls_messages[1].payload == expected);
  CHECK(transport->legacy_messages == legacy_count);
  transport->tls_send_result = false;
  CHECK_FALSE(channels.send_authenticated(
    bob.id(), ccf::consensus_msg, consensus.data(), consensus.size()));
  CHECK_FALSE(
    channels.send_encrypted(bob.id(), ccf::forwarded_msg, forwarding, body));
  CHECK(transport->tls_messages.size() == 4);
  CHECK(transport->legacy_messages == legacy_count);
  transport->tls_send_result = true;
  channels.set_endorsed_node_cert(alice.cert);
  CHECK(transport->identities == 2);
  channels.set_idle_timeout(1ms);
  channels.tick(2ms);
  CHECK(transport->legacy_closes == 1);
  CHECK(transport->tls_closes == 0);
  channels.close_channel(bob.id());
  CHECK(transport->tls_closes == 1);
  channels.associate_node_tls_address(bob.id(), "127.0.0.1:1");
  channels.send_authenticated(
    bob.id(), ccf::consensus_msg, consensus.data(), consensus.size());
  CHECK(transport->tls_messages.size() == 5);
}

int main(int argc, char** argv)
{
  signal(SIGPIPE, SIG_IGN);
  ccf::tasks::set_task_threads(2);
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  const auto result = context.run();
  ccf::tasks::set_task_threads(0);
  OPENSSL_cleanup();
  return result;
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "tls/openssl_connection_engine.h"
#include "tls/test/tls_test_helpers.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <doctest/doctest.h>
#include <fcntl.h>
#include <future>
#include <mutex>
#include <optional>
#include <poll.h>
#include <string>
#include <string_view>
#include <thread>

[[nodiscard]] size_t tls_test_poll_starts();

namespace
{
  using namespace ccf::tls;
  using namespace ccf::tls::test;
  using namespace std::chrono_literals;
  constexpr size_t RECORD_SIZE = 16384;

  // A TLS 1.3 ciphersuite outside the policy's AES-GCM list which this OpenSSL
  // build can negotiate. Platform providers, such as SymCrypt in FIPS
  // configurations, may leave ChaCha20-Poly1305 out.
  std::optional<std::string> negotiable_non_gcm_suite()
  {
    for (const char* suite :
         {"TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256"})
    {
      auto context = make_client_context();
      if (SSL_CTX_set_ciphersuites(context.get(), suite) != 1)
      {
        continue;
      }
      std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
        SSL_new(context.get()), SSL_free);
      REQUIRE(ssl != nullptr);
      std::unique_ptr<STACK_OF(SSL_CIPHER), void (*)(STACK_OF(SSL_CIPHER)*)>
        supported(SSL_get1_supported_ciphers(ssl.get()), [](auto* ciphers) {
          sk_SSL_CIPHER_free(ciphers);
        });
      for (int index = 0; index < sk_SSL_CIPHER_num(supported.get()); ++index)
      {
        const auto* cipher = sk_SSL_CIPHER_value(supported.get(), index);
        if (std::string_view(SSL_CIPHER_get_name(cipher)) == suite)
        {
          std::unique_ptr<EVP_CIPHER, decltype(&EVP_CIPHER_free)>
            implementation(
              EVP_CIPHER_fetch(
                nullptr,
                OBJ_nid2sn(SSL_CIPHER_get_cipher_nid(cipher)),
                nullptr),
              EVP_CIPHER_free);
          if (implementation != nullptr)
          {
            return suite;
          }
          ERR_clear_error();
        }
      }
    }
    return std::nullopt;
  }

  struct WriteGate
  {
    std::atomic<bool> block{true};
    std::atomic<bool> notified{false};
    std::promise<void> blocked;
    bool application = false;
    bool observe_socket_retries = false;
    std::shared_ptr<InboundAdmission> pause_reads_on_admission;
    std::atomic<uint64_t> socket_records{0};
    std::function<void()> notify;
    std::function<void()> on_write;

    void install(SSL* connection)
    {
      BIO* output = SSL_get_wbio(connection);
      BIO_set_callback_arg(output, reinterpret_cast<char*>(this));
      BIO_set_callback_ex(
        output,
        [](
          BIO* bio,
          int operation,
          const char* /*data*/,
          size_t size,
          int /*number*/,
          long /*argument*/,
          int result,
          size_t* /*processed*/) -> long {
          auto& gate = *reinterpret_cast<WriteGate*>(BIO_get_callback_arg(bio));
          if (operation == BIO_CB_WRITE && gate.on_write)
          {
            gate.on_write();
          }
          // Close the admission-check/syscall race when constructing a
          // completely full socket in the reciprocal-backpressure test.
          if (
            operation == BIO_CB_READ && gate.pause_reads_on_admission &&
            gate.pause_reads_on_admission->saturated())
          {
            BIO_set_retry_read(bio);
            return -1;
          }
          if (
            gate.observe_socket_retries &&
            operation == (BIO_CB_WRITE | BIO_CB_RETURN) && result > 0 &&
            size == 23)
          {
            ++gate.socket_records;
            gate.notify();
          }
          if (
            gate.observe_socket_retries &&
            operation == (BIO_CB_WRITE | BIO_CB_RETURN) && result <= 0 &&
            BIO_should_write(bio) && size == 27 &&
            !gate.notified.exchange(true))
          {
            gate.blocked.set_value();
          }
          // KeyUpdate: header + five-byte message + inner type + GCM tag.
          if (
            operation == BIO_CB_WRITE && gate.block &&
            (size == 27 || gate.application))
          {
            BIO_set_retry_write(bio);
            if (!gate.notified.exchange(true))
            {
              gate.blocked.set_value();
            }
            return -1;
          }
          return result;
        });
    }
  };

  struct KeyEvents
  {
    std::atomic<size_t> buffered_input{0};
    std::array<std::atomic<size_t>, 2> updates{};
    size_t records = 0;
    size_t epoch_records = 0;
    size_t max_epoch = 0;
    size_t requests = 0;
    size_t peer_updates = 0;
    bool active = false;
    std::function<void()> notify;

    static void keys(const SSL* ssl, const char* line)
    {
      auto& events =
        *static_cast<KeyEvents*>(SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
      const std::string_view label(line);
      // Count labels only; do not retain or print traffic secrets.
      if (label.starts_with("SERVER_TRAFFIC_SECRET_N "))
      {
        ++events.updates[0];
      }
      if (label.starts_with("CLIENT_TRAFFIC_SECRET_N "))
      {
        ++events.updates[1];
      }
      events.notify();
    }

    static void messages(
      int writing,
      int /*version*/,
      int type,
      const void* data,
      size_t size,
      SSL* /*ssl*/,
      void* arg)
    {
      if (writing != 0 || !static_cast<KeyEvents*>(arg)->active)
      {
        return;
      }
      auto& events = *static_cast<KeyEvents*>(arg);
      const auto* bytes = static_cast<const uint8_t*>(data);
      if (type == SSL3_RT_INNER_CONTENT_TYPE)
      {
        ++events.records;
        events.max_epoch = std::max(events.max_epoch, ++events.epoch_records);
      }
      if (
        type == SSL3_RT_HANDSHAKE && size == 5 &&
        bytes[0] == SSL3_MT_KEY_UPDATE)
      {
        events.epoch_records = 0;
        ++events.peer_updates;
        events.requests += bytes[4] == SSL_KEY_UPDATE_REQUESTED ? 1 : 0;
      }
    }
  };

  struct PairConfig
  {
    bool engine_peer = true;
    std::array<std::optional<uint64_t>, 2> budgets{8, 8};
    std::array<WriteGate*, 2> gates{};
    int version = TLS1_3_VERSION;
    int send_buffer = 4096;
    std::shared_ptr<InboundAdmission> admission = nullptr;
    bool shared_admission = false;
    std::shared_ptr<InboundAdmission> peer_admission = nullptr;
    bool charge_admission = false;
    std::function<void(size_t)> on_data = nullptr;
    const char* server_ciphersuites = nullptr;
  };

  struct EnginePair : public AsyncTest
  {
    uv_loop_t loop{};
    UVLoopRunner runner;
    std::array<std::vector<uint8_t>, 2> received;
    std::array<size_t, 2> handshakes{};
    std::array<size_t, 2> closes{};
    std::array<KeyEvents, 2> events;
    std::array<std::shared_ptr<SSL_CTX>, 2> contexts;
    std::array<std::shared_ptr<OpenSSLConnectionEngine>, 2> engines;
    std::array<SSL*, 2> connections{};
    int peer_fd = -1;
    std::unique_ptr<SSL, decltype(&SSL_free)> peer{nullptr, SSL_free};

    explicit EnginePair(PairConfig config = {})
    {
      REQUIRE(uv_loop_init(&loop) == 0);
      const auto [cert, key] = make_server_cert();
      contexts = {make_server_context(cert, key), make_client_context()};
      REQUIRE(SSL_CTX_set_num_tickets(contexts[0].get(), 0) == 1);
      if (config.server_ciphersuites != nullptr)
      {
        REQUIRE(
          SSL_CTX_set_ciphersuites(
            contexts[0].get(), config.server_ciphersuites) == 1);
      }
      int sockets[2];
      REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
      for (size_t side = 0; side < 2; ++side)
      {
        REQUIRE(contexts[side] != nullptr);
        events[side].notify = [this]() {
          std::lock_guard lock(mutex);
          cv.notify_all();
        };
        REQUIRE(
          SSL_CTX_set_max_proto_version(contexts[side].get(), config.version) ==
          1);
        SSL_CTX_set_app_data(contexts[side].get(), &events[side]);
        SSL_CTX_set_keylog_callback(contexts[side].get(), KeyEvents::keys);
        REQUIRE(fcntl(sockets[side], F_SETFL, O_NONBLOCK) == 0);
        if (side == 1 && !config.engine_peer)
        {
          peer_fd = sockets[side];
          peer.reset(SSL_new(contexts[side].get()));
          REQUIRE(peer != nullptr);
          REQUIRE(SSL_set_fd(peer.get(), peer_fd) == 1);
          SSL_set_msg_callback(peer.get(), KeyEvents::messages);
          SSL_set_msg_callback_arg(peer.get(), &events[side]);
          continue;
        }
        REQUIRE(
          setsockopt(
            sockets[side],
            SOL_SOCKET,
            SO_SNDBUF,
            &config.send_buffer,
            sizeof(config.send_buffer)) == 0);
        if (config.budgets[side])
        {
          REQUIRE(
            SSL_CTX_set_split_send_fragment(contexts[side].get(), 512) == 1);
          SSL_CTX_set_options(contexts[side].get(), SSL_OP_ENABLE_KTLS);
        }
        const auto budget = config.budgets[side];
        const auto admission = side == 0 || config.shared_admission ?
          config.admission :
          config.peer_admission;
        engines[side] = std::make_shared<OpenSSLConnectionEngine>(
          OpenSSLConnectionEngine::Config{
            .loop = &loop,
            .inbound_admission = admission,
            .on_handshake =
              [this, side, gate = config.gates[side], fd = sockets[side]](
                ::tcp::ConnID, SSL* ssl, bool) {
                CHECK(SSL_get_fd(ssl) == fd);
                connections[side] = ssl;
                if (gate != nullptr)
                {
                  gate->notify = events[side].notify;
                  gate->install(ssl);
                }
                std::lock_guard lock(mutex);
                ++handshakes[side];
                cv.notify_all();
                return true;
              },
            .traffic_key_policy = budget ?
              std::optional{TrafficKeyPolicy{.record_budget = *budget}} :
              std::nullopt},
          [this,
           side,
           admission,
           charge = config.charge_admission,
           on_data = config.on_data](
            ::tcp::ConnID,
            std::vector<uint8_t> data,
            const std::vector<uint8_t>&,
            bool) {
            {
              std::lock_guard lock(mutex);
              received[side].insert(
                received[side].end(), data.begin(), data.end());
              if (charge && admission)
              {
                admission->queued(data.size());
                events[side].buffered_input =
                  BIO_ctrl_pending(SSL_get_rbio(connections[side]));
              }
              cv.notify_all();
            }
            if (on_data)
            {
              on_data(side);
            }
          },
          [this, side](::tcp::ConnID) {
            std::lock_guard lock(mutex);
            ++closes[side];
            cv.notify_all();
          });
        engines[side]->start();
        REQUIRE(engines[side]->adopt(
          {.id = 1,
           .fd = sockets[side],
           .tls_context = contexts[side],
           .outgoing = side == 1}));
      }
    }

    int peer_io(
      const std::function<int()>& operation,
      const std::function<bool()>& done = {})
    {
      const auto deadline = std::chrono::steady_clock::now() + 5s;
      for (;;)
      {
        ERR_clear_error();
        const int result = operation();
        if (result > 0 || (done && done()))
        {
          return result;
        }
        const int error = SSL_get_error(peer.get(), result);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        {
          INFO(
            "OpenSSL error: " << error << ", "
                              << ccf::crypto::OpenSSL::first_error());
          return result;
        }
        const auto remaining =
          std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        REQUIRE(remaining.count() > 0);
        pollfd poller{
          .fd = peer_fd,
          .events =
            static_cast<short>(error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT),
          .revents = 0};
        const int ready =
          ::poll(&poller, 1, static_cast<int>(remaining.count()));
        INFO(
          "SSL pending " << SSL_pending(peer.get()) << ", buffered "
                         << SSL_has_pending(peer.get()) << ", init "
                         << SSL_in_init(peer.get()));
        REQUIRE(ready == 1);
      }
    }

    void start(bool establish = true)
    {
      runner.start(&loop);
      if (!establish)
      {
        return;
      }
      if (peer)
      {
        REQUIRE(peer_io([this]() { return SSL_connect(peer.get()); }) == 1);
        events[1].active = true;
      }
      REQUIRE(wait(
        [&]() { return handshakes[0] == 1 && (peer || handshakes[1] == 1); }));
    }

    void expect(size_t side, const std::vector<uint8_t>& data)
    {
      const bool complete =
        wait([&]() { return received[side].size() == data.size(); });
      std::lock_guard lock(mutex);
      INFO(
        "received " << received[side].size() << " of " << data.size()
                    << ", closes " << closes[0] << "/" << closes[1]);
      REQUIRE(complete);
      CHECK(received[side] == data);
    }

    void expect_peer_update(size_t requests = 1)
    {
      uint8_t byte = 0;
      peer_io(
        [&]() { return SSL_read(peer.get(), &byte, 1); },
        [&]() { return events[1].peer_updates != 0; });
      CHECK(events[1].peer_updates >= 1);
      CHECK(events[1].peer_updates <= requests);
      CHECK(events[1].requests == 0);
    }

    ~EnginePair()
    {
      const auto state = runner.thread.joinable() ?
        OpenSSLConnectionEngine::LoopState::Running :
        OpenSSLConnectionEngine::LoopState::NotRunning;
      for (auto& engine : engines)
      {
        if (engine)
        {
          engine->stop(state);
        }
      }
      runner.join();
      peer.reset();
      if (peer_fd >= 0)
      {
        ccf::tls::details::close_socket(peer_fd);
      }
      if (state == OpenSSLConnectionEngine::LoopState::NotRunning)
      {
        uv_run(&loop, UV_RUN_DEFAULT);
      }
      CHECK(uv_loop_close(&loop) == 0);
    }
  };

  TEST_CASE("Traffic keys update fragmented traffic in both directions")
  {
    WriteGate server_gate;
    WriteGate client_gate;
    auto server_blocked = server_gate.blocked.get_future();
    auto client_blocked = client_gate.blocked.get_future();
    PairConfig config;
    SUBCASE("Backpressure") {}
    SUBCASE("Large socket buffers")
    {
      config.send_buffer = 1024 * 1024;
    }
    SUBCASE("Minimum budget")
    {
      config.budgets = {2, 2};
    }
    SUBCASE("Default policy remains disabled")
    {
      config.budgets = {};
    }
    SUBCASE("Simultaneous blocked updates")
    {
      config.gates = {&server_gate, &client_gate};
      // Isolate control-write retries from the real socket-backpressure case
      // above: one artificial gate must not stop the other reaching its gate.
      config.send_buffer = 1024 * 1024;
    }
    EnginePair pair(config);
    pair.start();
    std::vector<uint8_t> data(size_t{32} * RECORD_SIZE);
    for (size_t index = 0; index < data.size(); ++index)
    {
      data[index] = static_cast<uint8_t>(index);
    }
    for (auto& engine : pair.engines)
    {
      engine->send(1, data.data(), data.size());
    }
    if (config.gates[0] != nullptr)
    {
      REQUIRE(server_blocked.wait_for(5s) == std::future_status::ready);
      REQUIRE(client_blocked.wait_for(5s) == std::future_status::ready);
      server_gate.block = false;
      client_gate.block = false;
    }
    for (size_t side = 0; side < 2; ++side)
    {
      pair.expect(side, data);
    }
    for (size_t side = 0; side < 2; ++side)
    {
      for (auto& updates : pair.events[side].updates)
      {
        CHECK((config.budgets[side] ? updates >= 4 : updates == 0));
      }
    }
  }

  TEST_CASE(
    "Traffic keys distinguish records from application messages and read "
    "chunks")
  {
    SUBCASE("Queued messages coalesce")
    {
      EnginePair pair;
      std::vector<uint8_t> data(40, 17);
      for (auto byte : data)
      {
        pair.engines[1]->send(1, &byte, 1);
      }
      pair.start();
      pair.expect(0, data);
      CHECK(pair.events[0].updates[1] == 0);
    }
    SUBCASE("Peer observes exact cipher epochs through fragmented reads")
    {
      const char* cipher = "TLS_AES_256_GCM_SHA384";
      SUBCASE("AES-256") {}
      SUBCASE("AES-128")
      {
        cipher = "TLS_AES_128_GCM_SHA256";
      }
      EnginePair pair({.engine_peer = false});
      REQUIRE(SSL_set_ciphersuites(pair.peer.get(), cipher) == 1);
      pair.start();
      const std::vector<uint8_t> data(size_t{20} * RECORD_SIZE, 37);
      pair.engines[0]->send(1, data.data(), data.size());
      std::vector<uint8_t> received;
      std::array<uint8_t, 997> chunk{};
      while (received.size() < data.size())
      {
        const int count = pair.peer_io([&]() {
          return SSL_read(pair.peer.get(), chunk.data(), chunk.size());
        });
        REQUIRE(count > 0);
        received.insert(received.end(), chunk.begin(), chunk.begin() + count);
      }
      CHECK(received == data);
      CHECK(pair.events[1].records == 22);
      CHECK(pair.events[1].peer_updates == 2);
      CHECK(pair.events[1].max_epoch == 8);
    }
  }

  TEST_CASE("Traffic keys reject peers that exceed the receive record budget")
  {
    EnginePair pair({.engine_peer = false});
    pair.start();
    const std::vector<uint8_t> data(size_t{9} * RECORD_SIZE, 42);
    REQUIRE(pair.peer_io([&]() {
      return SSL_write(pair.peer.get(), data.data(), data.size());
    }) == static_cast<int>(data.size()));
    REQUIRE(pair.wait([&]() { return pair.closes[0] == 1; }));
    pair.expect(0, std::vector<uint8_t>(size_t{8} * RECORD_SIZE, 42));
    CHECK(pair.events[0].updates[0] == 0);
    CHECK(pair.events[0].updates[1] == 0);
  }

  TEST_CASE("Traffic keys count peer KeyUpdate records against the budget")
  {
    EnginePair pair({.engine_peer = false});
    pair.start();
    const auto write_records = [&](size_t count) {
      const std::vector<uint8_t> data(count * RECORD_SIZE, 42);
      REQUIRE(pair.peer_io([&]() {
        return SSL_write(pair.peer.get(), data.data(), data.size());
      }) == static_cast<int>(data.size()));
    };
    const auto key_update = [&]() {
      REQUIRE(
        SSL_key_update(pair.peer.get(), SSL_KEY_UPDATE_NOT_REQUESTED) == 1);
      REQUIRE(
        pair.peer_io([&]() { return SSL_do_handshake(pair.peer.get()); }) == 1);
    };
    SUBCASE("The final record under a key may be the KeyUpdate itself")
    {
      write_records(7);
      key_update();
      write_records(8);
      pair.expect(0, std::vector<uint8_t>(size_t{15} * RECORD_SIZE, 42));
      CHECK(pair.closes[0] == 0);
      CHECK(pair.events[0].updates[1] == 1);
    }
    SUBCASE("A KeyUpdate beyond the budget closes the connection")
    {
      write_records(8);
      key_update();
      REQUIRE(pair.wait([&]() { return pair.closes[0] == 1; }));
      pair.expect(0, std::vector<uint8_t>(size_t{8} * RECORD_SIZE, 42));
    }
  }

  TEST_CASE("Traffic keys survive repeated peer update requests")
  {
    constexpr size_t requests = 200;
    // The peer does not read until the end, so its socket must hold every
    // response; a full send buffer would be ordinary write backpressure.
    EnginePair pair({.engine_peer = false, .send_buffer = 1024 * 1024});
    pair.start();
    for (size_t request = 0; request < requests; ++request)
    {
      REQUIRE(SSL_key_update(pair.peer.get(), SSL_KEY_UPDATE_REQUESTED) == 1);
      REQUIRE(
        pair.peer_io([&]() { return SSL_do_handshake(pair.peer.get()); }) == 1);
    }
    // Every request installs a new receive key and is answered under the old
    // sending key. Neither direction may trip the engine's own accounting.
    const bool complete =
      pair.wait([&]() { return pair.events[0].updates[1] == requests; });
    INFO("Receive key updates: " << pair.events[0].updates[1].load());
    INFO("Sending key updates: " << pair.events[0].updates[0].load());
    REQUIRE(complete);
    CHECK(pair.events[0].updates[0] >= 1);
    CHECK(pair.events[0].updates[0] <= requests);
    CHECK(pair.closes[0] == 0);
    const uint8_t marker = 17;
    pair.engines[0]->send(1, &marker, 1);
    uint8_t received_marker = 0;
    REQUIRE(pair.peer_io([&]() {
      return SSL_read(pair.peer.get(), &received_marker, 1);
    }) == 1);
    CHECK(received_marker == marker);
    pair.expect_peer_update(requests);
    REQUIRE(SSL_write(pair.peer.get(), "x", 1) == 1);
    pair.expect(0, {'x'});
    CHECK(pair.closes[0] == 0);
  }

  TEST_CASE("Traffic keys preserve blocked updates, partial writes and close")
  {
    WriteGate gate;
    auto blocked = gate.blocked.get_future();
    EnginePair pair({.gates = {&gate, nullptr}});
    pair.start();
    const std::vector<uint8_t> prefix(size_t{8} * RECORD_SIZE, 42);
    pair.engines[0]->send(1, prefix.data(), prefix.size());
    REQUIRE(blocked.wait_for(5s) == std::future_status::ready);
    SUBCASE("Resume with appended output and graceful close")
    {
      const std::vector<uint8_t> tail(2000, 17);
      pair.engines[0]->send(1, tail.data(), tail.size());
      pair.engines[0]->close_connection(1);
      gate.block = false;
      auto data = prefix;
      data.insert(data.end(), tail.begin(), tail.end());
      pair.expect(1, data);
      REQUIRE(pair.wait([&]() { return pair.closes[0] == 1; }));
    }
    SUBCASE("Forced stop")
    {
      pair.engines[0]->stop(OpenSSLConnectionEngine::LoopState::Running);
      CHECK(pair.closes[0] == 1);
    }
    SUBCASE("Peer close")
    {
      pair.engines[1]->stop(OpenSSLConnectionEngine::LoopState::Running);
      gate.block = false;
      REQUIRE(pair.wait([&]() { return pair.closes[0] == 1; }));
    }
  }

  TEST_CASE("Traffic keys answer requests before the next application record")
  {
    bool pending_write = false;
    size_t requests = 1;
    SUBCASE("No pending write") {}
    SUBCASE("During a pending application write")
    {
      pending_write = true;
    }
    SUBCASE("Repeated requests during a pending application write")
    {
      pending_write = true;
      requests = 2;
    }
    WriteGate gate;
    gate.application = true;
    auto blocked = gate.blocked.get_future();
    EnginePair pair(
      {.engine_peer = false,
       .gates = {pending_write ? &gate : nullptr, nullptr}});
    pair.start();
    const std::vector<uint8_t> data(1000, 42);
    if (pending_write)
    {
      pair.engines[0]->send(1, data.data(), data.size());
      REQUIRE(blocked.wait_for(5s) == std::future_status::ready);
    }
    for (size_t request = 0; request < requests; ++request)
    {
      REQUIRE(SSL_key_update(pair.peer.get(), SSL_KEY_UPDATE_REQUESTED) == 1);
      REQUIRE(
        pair.peer_io([&]() { return SSL_do_handshake(pair.peer.get()); }) == 1);
    }
    // The marker must be queued after the request is received, not merely
    // sent: already-in-flight application data may precede the response.
    REQUIRE(pair.wait([&]() { return pair.events[0].updates[1] >= 1; }));
    if (pending_write)
    {
      REQUIRE(SSL_write(pair.peer.get(), "x", 1) == 1);
      gate.block = false;
      std::vector<uint8_t> received(data.size());
      REQUIRE(pair.peer_io([&]() {
        return SSL_read(pair.peer.get(), received.data(), received.size());
      }) == static_cast<int>(received.size()));
      CHECK(received == data);
      pair.expect(0, {'x'});
      CHECK(pair.events[0].updates[1] == requests);
    }
    const uint8_t marker = 17;
    pair.engines[0]->send(1, &marker, 1);
    uint8_t received_marker = 0;
    REQUIRE(pair.peer_io([&]() {
      return SSL_read(pair.peer.get(), &received_marker, 1);
    }) == 1);
    CHECK(received_marker == marker);
    pair.expect_peer_update(requests);
  }

  TEST_CASE(
    "Traffic keys resume control input after yielding to a queued response")
  {
    auto admission = std::make_shared<InboundAdmission>(1);
    WriteGate gate;
    gate.block = false;
    gate.pause_reads_on_admission = admission;
    EnginePair pair(
      {.engine_peer = false,
       .gates = {&gate, nullptr},
       .admission = admission,
       .charge_admission = true});
    pair.start();
    admission->queued(1);
    REQUIRE(SSL_write(pair.peer.get(), "x", 1) == 1);
    for (size_t request = 0; request < 2; ++request)
    {
      REQUIRE(SSL_key_update(pair.peer.get(), SSL_KEY_UPDATE_REQUESTED) == 1);
      REQUIRE(
        pair.peer_io([&]() { return SSL_do_handshake(pair.peer.get()); }) == 1);
    }
    admission->consumed(1);
    pair.expect(0, {'x'});
    REQUIRE(pair.events[0].buffered_input == 54);
    const uint8_t marker = 17;
    pair.engines[0]->send(1, &marker, 1);
    admission->consumed(1);
    uint8_t received = 0;
    REQUIRE(pair.peer_io([&]() {
      return SSL_read(pair.peer.get(), &received, 1);
    }) == 1);
    CHECK(received == marker);
    // No application input or further socket event should be necessary to
    // process a control record OpenSSL held while yielding to that marker.
    REQUIRE(pair.wait([&]() { return pair.events[0].updates[1] == 2; }));
    pair.expect_peer_update(2);
  }

  TEST_CASE("Traffic keys reject TLS 1.2 only when opted in")
  {
    PairConfig config{.engine_peer = false, .version = TLS1_2_VERSION};
    SUBCASE("Accepted policy") {}
    SUBCASE("Initiating policy")
    {
      config.engine_peer = true;
      config.budgets = {std::nullopt, 8};
    }
    SUBCASE("Default RPC behavior")
    {
      config.budgets = {};
    }
    EnginePair pair(config);
    pair.start(false);
    if (!config.budgets[0] && !config.budgets[1])
    {
      REQUIRE(
        pair.peer_io([&]() { return SSL_connect(pair.peer.get()); }) == 1);
      CHECK(SSL_version(pair.peer.get()) == TLS1_2_VERSION);
      REQUIRE(SSL_write(pair.peer.get(), "rpc", 3) == 3);
      pair.expect(0, {'r', 'p', 'c'});
    }
    else
    {
      if (pair.peer)
      {
        ERR_clear_error();
        CHECK(
          pair.peer_io([&]() { return SSL_connect(pair.peer.get()); }) != 1);
      }
      REQUIRE(pair.wait([&]() { return pair.closes[0] == 1; }));
      CHECK(pair.handshakes[0] == 0);
      CHECK(pair.handshakes[1] == 0);
    }
  }

  TEST_CASE("Traffic keys reject non-AES-GCM ciphersuites only when opted in")
  {
    const auto suite = negotiable_non_gcm_suite();
    if (!suite)
    {
      MESSAGE("no non-AES-GCM TLS 1.3 ciphersuite is negotiable; skipping");
      return;
    }
    // The server context permits the suite alongside AES-GCM, so a refusal
    // can only come from the per-connection policy.
    const std::string permissive = *suite + ":TLS_AES_256_GCM_SHA384";
    PairConfig config{
      .engine_peer = false, .server_ciphersuites = permissive.c_str()};
    SUBCASE("Accepted policy") {}
    SUBCASE("Initiating policy")
    {
      config.engine_peer = true;
      config.budgets = {std::nullopt, 8};
      config.server_ciphersuites = suite->c_str();
    }
    // The engine adds no ciphersuite restriction of its own without the
    // policy; production RPC contexts restrict TLS 1.3 to AES-GCM separately.
    SUBCASE("Policy disabled")
    {
      config.budgets = {};
    }
    EnginePair pair(config);
    if (pair.peer)
    {
      REQUIRE(SSL_set_ciphersuites(pair.peer.get(), suite->c_str()) == 1);
    }
    pair.start(false);
    if (!config.budgets[0] && !config.budgets[1])
    {
      REQUIRE(
        pair.peer_io([&]() { return SSL_connect(pair.peer.get()); }) == 1);
      CHECK(std::string_view(SSL_get_cipher_name(pair.peer.get())) == *suite);
      REQUIRE(SSL_write(pair.peer.get(), "rpc", 3) == 3);
      pair.expect(0, {'r', 'p', 'c'});
    }
    else
    {
      if (pair.peer)
      {
        ERR_clear_error();
        CHECK(
          pair.peer_io([&]() { return SSL_connect(pair.peer.get()); }) != 1);
      }
      REQUIRE(pair.wait([&]() {
        return pair.closes[0] == 1 && (pair.peer || pair.closes[1] == 1);
      }));
      CHECK(pair.handshakes[0] == 0);
      CHECK(pair.handshakes[1] == 0);
    }
  }

  TEST_CASE("Traffic keys retain inbound admission during outbound progress")
  {
    auto admission = std::make_shared<InboundAdmission>(1);
    EnginePair pair({.admission = admission});
    pair.start();
    admission->queued(1);
    const std::vector<uint8_t> data(size_t{2} * RECORD_SIZE, 42);
    pair.engines[1]->send(1, data.data(), data.size());
    for (size_t count = 1; count <= 8; ++count)
    {
      const uint8_t byte = 17;
      pair.engines[0]->send(1, &byte, 1);
      pair.expect(1, std::vector<uint8_t>(count, byte));
      std::lock_guard lock(pair.mutex);
      CHECK(pair.received[0].empty());
    }
    admission->consumed(1);
    pair.expect(0, data);
  }

  TEST_CASE(
    "Traffic keys give responses a turn during sustained incoming traffic")
  {
    size_t fragment = RECORD_SIZE;
    SUBCASE("Full-sized records") {}
    SUBCASE("Smaller records")
    {
      fragment = 4096;
    }
    WriteGate observer;
    observer.block = false;
    EnginePair* connection = nullptr;
    std::atomic<bool> response_queued{false};
    std::atomic<size_t> response_after{SIZE_MAX};
    const uint8_t marker = 17;
    EnginePair pair(
      {.engine_peer = false,
       .budgets = {1024, 1024},
       .gates = {&observer, nullptr},
       .on_data = [&](size_t side) {
         if (side == 0 && !response_queued.exchange(true))
         {
           connection->engines[0]->send(1, &marker, 1);
         }
       }});
    connection = &pair;
    observer.on_write = [&]() {
      std::lock_guard lock(pair.mutex);
      if (response_after == SIZE_MAX)
      {
        response_after = pair.received[0].size();
      }
    };
    REQUIRE(SSL_set_max_send_fragment(pair.peer.get(), fragment) == 1);
    pair.start();
    const std::vector<uint8_t> incoming(size_t{2} * 1024 * 1024, 42);
    REQUIRE(pair.peer_io([&]() {
      return SSL_write(pair.peer.get(), incoming.data(), incoming.size());
    }) == static_cast<int>(incoming.size()));
    uint8_t received = 0;
    REQUIRE(pair.peer_io([&]() {
      return SSL_read(pair.peer.get(), &received, 1);
    }) == 1);
    CHECK(received == marker);
    // At most an in-flight read pass, then one pass draining the fixed input
    // buffer, may precede the response. The whole stream must not go first.
    CHECK(response_after.load() <= size_t{128} * 1024);
    pair.expect(0, incoming);
  }

  TEST_CASE(
    "Traffic keys drain sockets when both local updates are write-blocked")
  {
    // Measure the small-record capacity rather than assuming a kernel-specific
    // AF_UNIX buffer overhead. One more record will be the pending KeyUpdate.
    int sockets[2];
    REQUIRE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) == 0);
    const int buffer = 4096;
    REQUIRE(
      setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer)) ==
      0);
    REQUIRE(fcntl(sockets[0], F_SETFL, O_NONBLOCK) == 0);
    const std::array<uint8_t, 23> record{};
    uint64_t records = 0;
    while (::send(sockets[0], record.data(), record.size(), MSG_NOSIGNAL) > 0)
    {
      ++records;
    }
    const int error = errno;
    details::close_socket(sockets[0]);
    details::close_socket(sockets[1]);
    REQUIRE(error == EAGAIN);
    REQUIRE(records > 0);
    auto admission = std::make_shared<InboundAdmission>(1);
    WriteGate server;
    WriteGate client;
    server.block = client.block = false;
    server.observe_socket_retries = client.observe_socket_retries = true;
    server.pause_reads_on_admission = client.pause_reads_on_admission =
      admission;
    auto server_blocked = server.blocked.get_future();
    auto client_blocked = client.blocked.get_future();
    EnginePair pair(
      {.budgets = {records + 1, records + 1},
       .gates = {&server, &client},
       .admission = admission,
       .shared_admission = true});
    pair.start();
    admission->queued(1);
    const uint8_t byte = 17;
    // Waiting for each record's syscall prevents queued sends coalescing.
    for (uint64_t index = 0; index <= records; ++index)
    {
      for (auto& engine : pair.engines)
      {
        engine->send(1, &byte, 1);
      }
      if (index < records)
      {
        REQUIRE(pair.wait([&]() {
          return server.socket_records > index && client.socket_records > index;
        }));
      }
    }
    REQUIRE(server_blocked.wait_for(5s) == std::future_status::ready);
    REQUIRE(client_blocked.wait_for(5s) == std::future_status::ready);
    {
      std::lock_guard lock(pair.mutex);
      CHECK(pair.received[0].empty());
      CHECK(pair.received[1].empty());
    }
    admission->consumed(1);
    const std::vector<uint8_t> expected(records + 1, byte);
    pair.expect(0, expected);
    pair.expect(1, expected);
  }

  TEST_CASE("Traffic keys pause read retries while inbound admission is full")
  {
    PairConfig config{.engine_peer = false};
    SUBCASE("Accepted policy") {}
    SUBCASE("Default RPC behavior")
    {
      config.budgets = {};
    }
    auto admission = std::make_shared<InboundAdmission>(1);
    WriteGate gate;
    auto blocked = gate.blocked.get_future();
    config.gates = {&gate, nullptr};
    config.admission = admission;
    EnginePair pair(config);
    pair.start();
    for (size_t request = 0; request < 2; ++request)
    {
      REQUIRE(SSL_key_update(pair.peer.get(), SSL_KEY_UPDATE_REQUESTED) == 1);
      REQUIRE(
        pair.peer_io([&]() { return SSL_do_handshake(pair.peer.get()); }) == 1);
    }
    // No application output was queued: the blocked write belongs to SSL_read.
    REQUIRE(blocked.wait_for(5s) == std::future_status::ready);
    admission->queued(1);
    const auto polls = tls_test_poll_starts();
    gate.block = false;
    std::this_thread::sleep_for(50ms);
    CHECK(tls_test_poll_starts() - polls <= 4);
    // A queued send dispatches the connection with its read retry outstanding
    // and no actionable poll events. Inbound data must stay in the socket.
    const std::vector<uint8_t> data(1000, 42);
    REQUIRE(pair.peer_io([&]() {
      return SSL_write(pair.peer.get(), data.data(), data.size());
    }) == static_cast<int>(data.size()));
    const uint8_t marker = 17;
    pair.engines[0]->send(1, &marker, 1);
    std::this_thread::sleep_for(50ms);
    {
      std::lock_guard lock(pair.mutex);
      CHECK(pair.received[0].empty());
    }
    admission->consumed(1);
    uint8_t received = 0;
    REQUIRE(pair.peer_io([&]() {
      return SSL_read(pair.peer.get(), &received, 1);
    }) == 1);
    CHECK(received == marker);
    pair.expect(0, data);
    pair.expect_peer_update(2);
  }

  TEST_CASE("Traffic keys drain old input before starting another KeyUpdate")
  {
    auto server_admission = std::make_shared<InboundAdmission>(1);
    auto client_admission = std::make_shared<InboundAdmission>(1);
    WriteGate server;
    WriteGate client;
    server.block = client.block = false;
    server.observe_socket_retries = client.observe_socket_retries = true;
    server.pause_reads_on_admission = server_admission;
    client.pause_reads_on_admission = client_admission;
    EnginePair pair(
      {.budgets = {3, 3},
       .gates = {&server, &client},
       .admission = server_admission,
       .peer_admission = client_admission,
       .charge_admission = true});
    pair.start();
    server_admission->queued(1);
    client_admission->queued(1);
    const uint8_t byte = 17;
    for (uint64_t record = 1; record <= 2; ++record)
    {
      for (auto& engine : pair.engines)
      {
        engine->send(1, &byte, 1);
      }
      REQUIRE(pair.wait([&]() {
        return server.socket_records == record &&
          client.socket_records == record;
      }));
    }
    server_admission->consumed(1);
    client_admission->consumed(1);
    pair.expect(0, {byte});
    pair.expect(1, {byte});
    // The first delivery pauses admission with the next record solely in BIO.
    REQUIRE(pair.events[0].buffered_input > 0);
    REQUIRE(pair.events[1].buffered_input > 0);
    for (auto& engine : pair.engines)
    {
      engine->send(1, &byte, 1);
    }
    std::this_thread::sleep_for(50ms);
    CHECK(server.socket_records == 2);
    CHECK(client.socket_records == 2);
    for (size_t size = 2; size <= 3; ++size)
    {
      server_admission->consumed(1);
      client_admission->consumed(1);
      pair.expect(0, std::vector<uint8_t>(size, byte));
      pair.expect(1, std::vector<uint8_t>(size, byte));
    }
    CHECK(pair.events[0].updates[1] == 1);
    CHECK(pair.events[1].updates[0] == 1);
  }

  TEST_CASE("Traffic keys reject invalid internal budgets")
  {
    for (uint64_t budget :
         {uint64_t{0}, uint64_t{1}, TrafficKeyPolicy::MAX_RECORD_BUDGET + 1})
    {
      CHECK_THROWS_AS(
        std::make_shared<OpenSSLConnectionEngine>(
          OpenSSLConnectionEngine::Config{
            .traffic_key_policy = TrafficKeyPolicy{.record_budget = budget}},
          OpenSSLConnectionEngine::OnData{}),
        std::invalid_argument);
    }
  }
}

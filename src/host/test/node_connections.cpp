// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "host/node_connections.h"

#include "consensus/consensus_types.h"
#include "kv/serialised_entry_format.h"
#include "tasks/job_board.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <chrono>
#include <cstring>
#include <doctest/doctest.h>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

using namespace std::chrono_literals;

// Surfaces the message of an unexpected exception in the failure output,
// rather than just reporting that something was thrown.
REGISTER_EXCEPTION_TRANSLATOR(const std::exception& e)
{
  return doctest::String(e.what());
}

namespace
{
  constexpr size_t default_max_frame_size = 1 << 20;

  // Node IDs are hex-encoded public key hashes. The two chosen here sit at
  // opposite ends of the ordering, so that any tie-break which depends on
  // their relative order is unambiguous.
  const std::string node_a_id(64, '0');
  const std::string node_b_id(64, 'f');

  class MockSocketImpl;

  // Handle mirroring the subset of asynchost::TCP (proxy_ptr<TCPImpl>) that
  // NodeConnections uses. Ownership is shared, so erasing an entry from the
  // connections map destroys the underlying socket, exactly as proxy_ptr does.
  class MockSocket
  {
  private:
    std::shared_ptr<MockSocketImpl> impl;

  public:
    MockSocket();
    MockSocket(std::nullptr_t) : impl(nullptr) {}
    MockSocket(bool /*is_client*/, std::optional<std::chrono::milliseconds>);

    MockSocketImpl* operator->() const
    {
      return impl.get();
    }

    [[nodiscard]] bool is_null() const
    {
      return impl == nullptr;
    }

    [[nodiscard]] MockSocketImpl* get() const
    {
      return impl.get();
    }
  };

  // An in-process stand-in for the network. It gives the test explicit control
  // over when connections complete, when bytes are delivered, and crucially
  // whether the closure of one end of a connection is ever observed by the
  // other end.
  struct MockNet
  {
    struct PendingConnect
    {
      MockSocketImpl* initiator;
      std::string host;
      std::string port;
    };

    std::map<std::string, MockSocketImpl*> listeners;
    std::vector<PendingConnect> pending_connects;
    std::set<MockSocketImpl*> live_sockets;
    // Which sockets each listener has accepted, so a test can reach the
    // far end of a specific connection.
    std::vector<std::pair<MockSocketImpl*, MockSocketImpl*>> accepted;
    size_t next_port = 1000;

    // When false, destroying one end of a connection does not notify the other
    // end. This models a link where the FIN is silently dropped rather than
    // delivered: a firewall DROP rule, a NAT eviction, or a blackholing SDN.
    // Without this, a dead socket is self-announcing and the bug under test
    // cannot occur.
    bool deliver_close = true;

    static std::string key(const std::string& host, const std::string& port)
    {
      return host + ":" + port;
    }
  };

  MockNet* net = nullptr;

  class MockSocketImpl : public std::enable_shared_from_this<MockSocketImpl>
  {
  public:
    std::unique_ptr<asynchost::SocketBehaviour<MockSocket>> behaviour;
    std::string host;
    std::string port;
    MockSocketImpl* peer = nullptr;
    std::vector<uint8_t> rx;

    // Writes issued before the connection completes are buffered and flushed
    // on connect, as libuv does via TCPImpl::pending_writes. Without this a
    // node's first message to a peer would be lost, which never happens in
    // practice and would mask the behaviour under test.
    bool connected = false;
    std::vector<uint8_t> pending_tx;

    MockSocketImpl()
    {
      net->live_sockets.insert(this);
    }

    ~MockSocketImpl()
    {
      net->live_sockets.erase(this);
      sever();
    }

    // Detach from the far end, notifying it only if the network is currently
    // delivering connection teardown.
    void sever()
    {
      if (peer != nullptr)
      {
        auto* p = peer;
        peer = nullptr;
        p->peer = nullptr;
        if (net->deliver_close && p->behaviour != nullptr)
        {
          // As with TCP, bytes written before the close are read before the
          // far end observes it
          if (!p->rx.empty())
          {
            auto data = std::exchange(p->rx, {});
            uint8_t* ptr = data.data();
            p->behaviour->on_read(data.size(), ptr, {});
          }
          p->behaviour->on_disconnect();
        }
      }
    }

    void on_connected(MockSocketImpl* far_end)
    {
      peer = far_end;
      connected = true;
      if (!pending_tx.empty())
      {
        peer->rx.insert(peer->rx.end(), pending_tx.begin(), pending_tx.end());
        pending_tx.clear();
      }
    }

    void set_behaviour(
      std::unique_ptr<asynchost::SocketBehaviour<MockSocket>> b)
    {
      behaviour = std::move(b);
    }

    [[nodiscard]] std::string get_host() const
    {
      return host;
    }

    [[nodiscard]] std::string get_port() const
    {
      return port;
    }

    bool listen(
      const std::string& host_,
      const std::string& port_,
      const std::optional<std::string>& = std::nullopt)
    {
      host = host_;
      port = port_ == "0" ? std::to_string(net->next_port++) : port_;
      net->listeners[MockNet::key(host, port)] = this;
      return true;
    }

    bool connect(
      const std::string& host_,
      const std::string& port_,
      const std::optional<std::string>& = std::nullopt)
    {
      net->pending_connects.push_back({this, host_, port_});
      return true;
    }

    bool write(size_t len, const uint8_t* data, sockaddr = {})
    {
      if (!connected)
      {
        pending_tx.insert(pending_tx.end(), data, data + len);
        return true;
      }

      if (peer == nullptr)
      {
        // Writing into a socket whose far end is gone. As with a real
        // blackholed TCP connection this silently succeeds, and the bytes are
        // never seen again.
        return true;
      }

      peer->rx.insert(peer->rx.end(), data, data + len);
      return true;
    }
  };

  MockSocket::MockSocket() : impl(std::make_shared<MockSocketImpl>()) {}
  MockSocket::MockSocket(bool, std::optional<std::chrono::milliseconds>) :
    impl(std::make_shared<MockSocketImpl>())
  {}

  // Complete every outstanding connect at once. Batching them is what makes
  // the simultaneous-connect race deterministic: both nodes have dialled each
  // other before either has accepted.
  void complete_connects()
  {
    auto pending = std::move(net->pending_connects);
    net->pending_connects.clear();

    for (const auto& p : pending)
    {
      auto listener = net->listeners.find(MockNet::key(p.host, p.port));
      REQUIRE(listener != net->listeners.end());

      // The accepted socket is the far end of the initiator's socket. on_accept
      // takes ownership of it, as NodeServerBehaviour does for a real peer.
      auto accepted = MockSocket();
      accepted->connected = true;
      accepted->peer = p.initiator;

      listener->second->behaviour->on_accept(accepted);
      net->accepted.emplace_back(listener->second, accepted.get());
      p.initiator->on_connected(accepted.get());
      p.initiator->behaviour->on_connect();
    }
  }

  // Deliver buffered bytes to the behaviour on each receiving socket, repeating
  // until the network is quiescent.
  void pump()
  {
    for (size_t round = 0; round < 8; ++round)
    {
      std::vector<MockSocketImpl*> with_data;
      for (auto* s : net->live_sockets)
      {
        if (!s->rx.empty() && s->behaviour != nullptr)
        {
          with_data.push_back(s);
        }
      }

      if (with_data.empty())
      {
        return;
      }

      for (auto* s : with_data)
      {
        // The socket may have been destroyed by an earlier delivery in this
        // same round.
        if (net->live_sockets.find(s) == net->live_sockets.end())
        {
          continue;
        }

        auto data = s->rx;
        s->rx.clear();
        uint8_t* ptr = data.data();
        if (!s->behaviour->on_read(data.size(), ptr, {}))
        {
          // Returning false from on_read closes the connection, as it does for
          // a real socket. Keep the socket alive across the callback, since
          // its owner will typically drop it in response.
          auto keep_alive = s->shared_from_this();
          s->sever();
          s->behaviour->on_disconnect();
        }
      }
    }
  }

  // The host inspects the raft header of every outbound consensus message, so
  // the payload has to be a plausible one. A pre-vote is used here because it
  // is what a stalled candidate sends, and unlike an append-entries it carries
  // no ledger indices for the host to read.
  std::vector<uint8_t> make_pre_vote()
  {
    std::vector<uint8_t> m(sizeof(aft::Node2NodeMsg) + 16, 0);
    const auto type =
      static_cast<aft::Node2NodeMsg>(aft::raft_request_pre_vote);
    std::memcpy(m.data(), &type, sizeof(type));
    return m;
  }

  // The socket a given listener most recently accepted, or nullptr.
  MockSocketImpl* last_accepted_by(MockSocketImpl* listener)
  {
    MockSocketImpl* found = nullptr;
    for (const auto& [l, a] : net->accepted)
    {
      if (l == listener && net->live_sockets.count(a) > 0)
      {
        found = a;
      }
    }
    return found;
  }

  // Stands in for the node: records every inbound frame the transport
  // delivers, with the owned payload it was given.
  struct RecordingInbound : public ccf::NodeInboundHandler
  {
    struct Frame
    {
      ccf::NodeMsgType type;
      ccf::NodeId from;
      std::vector<uint8_t> payload;
    };

    std::vector<Frame> frames;

    void recv_node_inbound(
      ccf::NodeMsgType type,
      const ccf::NodeId& from,
      std::vector<uint8_t>&& payload) override
    {
      frames.push_back({type, from, std::move(payload)});
    }
  };

  struct TestNode
  {
    std::filesystem::path ledger_dir;
    std::unique_ptr<asynchost::Ledger> ledger;
    ccf::tasks::JobBoard job_board;
    std::unique_ptr<asynchost::LedgerSubsystem> ledger_subsystem;
    std::shared_ptr<asynchost::NodeConnectionsImpl<MockSocket>> connections;
    std::shared_ptr<RecordingInbound> inbound =
      std::make_shared<RecordingInbound>();

    std::string host;
    std::string port;
    size_t received = 0;

    TestNode(
      const std::string& name,
      std::string host_,
      size_t max_frame_size = default_max_frame_size) :
      ledger_dir(
        std::filesystem::temp_directory_path() / ("nc_test_ledger_" + name)),
      host(std::move(host_)),
      port("0")
    {
      std::filesystem::remove_all(ledger_dir);
      ledger = std::make_unique<asynchost::Ledger>(ledger_dir.string());
      ledger_subsystem =
        std::make_unique<asynchost::LedgerSubsystem>(*ledger, 1024, job_board);
      connections =
        std::make_shared<asynchost::NodeConnectionsImpl<MockSocket>>(
          *ledger,
          *ledger_subsystem,
          host,
          port,
          max_frame_size,
          std::nullopt,
          2s);
      connections->set_inbound_handler(inbound);
    }

    ~TestNode()
    {
      connections.reset();
      ledger_subsystem.reset();
      ledger.reset();
      std::filesystem::remove_all(ledger_dir);
    }

    // Mirrors production: run the ledger lane, then apply the results on the
    // (here, only) thread that owns the sockets.
    void drain_to_host()
    {
      while (auto task = job_board.get_task())
      {
        task->do_task();
      }
      connections->flush_outbound();
    }

    // Inbound frames are delivered synchronously to the handler
    void drain_to_enclave()
    {
      received = inbound->frames.size();
    }

    void send_to(const std::string& peer_id, const std::vector<uint8_t>& body)
    {
      connections->send(
        peer_id,
        ccf::NodeMsgType::consensus_msg,
        self_id,
        std::vector<uint8_t>(body));
    }

    void learn_address(
      const std::string& peer_id,
      const std::string& peer_host,
      const std::string& peer_port)
    {
      connections->associate_node_address(peer_id, peer_host, peer_port);
    }

    std::string self_id;
  };

  // A connection opened directly by the test, so that it can write arbitrary
  // (including malformed) bytes to a node.
  struct RawBehaviour : public asynchost::SocketBehaviour<MockSocket>
  {
    RawBehaviour() : asynchost::SocketBehaviour<MockSocket>("Raw", "TCP") {}
  };

  MockSocket connect_raw(const TestNode& target)
  {
    auto raw = MockSocket(true, std::nullopt);
    raw->set_behaviour(std::make_unique<RawBehaviour>());
    raw->connect(target.host, target.port);
    complete_connects();
    return raw;
  }

  std::vector<uint8_t> make_ledger_entry(uint8_t fill, size_t size)
  {
    std::vector<uint8_t> entry(ccf::kv::serialised_entry_header_size + size);
    auto* data = entry.data();
    auto remaining = entry.size();
    ccf::kv::SerialisedEntryHeader header;
    header.set_size(size);
    serialized::write(data, remaining, header);
    std::fill(data, data + remaining, fill);
    return entry;
  }

  // The prefix of an AppendEntries covering (prev_idx, idx], as far as the host
  // inspects it, followed by some bytes standing in for the rest of the
  // authenticated message.
  std::vector<uint8_t> make_append_entries(
    ::consensus::Index prev_idx, ::consensus::Index idx)
  {
    const auto type = static_cast<aft::Node2NodeMsg>(aft::raft_append_entries);
    const ::consensus::AppendEntriesIndex ae{.idx = idx, .prev_idx = prev_idx};
    std::vector<uint8_t> m(sizeof(type) + sizeof(ae) + 16, 0xab);
    std::memcpy(m.data(), &type, sizeof(type));
    std::memcpy(m.data() + sizeof(type), &ae, sizeof(ae));
    return m;
  }
}

// Regression test for the node-to-node channel stall investigated in #8232.
//
// When two nodes dial each other at the same moment, each ends up with both an
// outgoing connection it created and an incoming connection the peer created.
// If both nodes independently decide to keep the incoming one, they each
// destroy the socket the other is relying on, and both are left holding a
// connection whose far end no longer exists.
//
// On a healthy network this is self-correcting, because closing a socket sends
// a FIN which the peer observes as a disconnect. It is not self-correcting when
// that notification is lost, which is exactly what a partition does. The result
// is two nodes that believe they are connected, silently writing consensus
// messages into dead sockets indefinitely.
TEST_CASE("Simultaneous connect leaves a usable connection in both directions")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    TestNode b("b", "10.0.0.2");
    a.self_id = node_a_id;
    b.self_id = node_b_id;

    a.learn_address(node_b_id, b.host, b.port);
    b.learn_address(node_a_id, a.host, a.port);
    a.drain_to_host();
    b.drain_to_host();

    const auto payload = make_pre_vote();

    // Both nodes send to each other before either has accepted a connection.
    // This is the simultaneous-connect race.
    a.send_to(node_b_id, payload);
    b.send_to(node_a_id, payload);
    a.drain_to_host();
    b.drain_to_host();

    // From here the link silently swallows connection teardown, so neither node
    // can rely on TCP to tell it that a socket has become useless.
    mock_net.deliver_close = false;

    complete_connects();
    pump();
    a.drain_to_enclave();
    b.drain_to_enclave();

    // Whichever connection survived the race, it must actually carry traffic.
    // Send again in both directions and require both messages to arrive.
    const auto a_before = a.received;
    const auto b_before = b.received;

    a.send_to(node_b_id, payload);
    b.send_to(node_a_id, payload);
    a.drain_to_host();
    b.drain_to_host();
    pump();
    a.drain_to_enclave();
    b.drain_to_enclave();

    CHECK(b.received > b_before);
    CHECK(a.received > a_before);
  }

  net = nullptr;
}

// Defending our own outgoing connection is only correct while a genuine race
// could be in progress. A peer which connects to us later is telling us it
// believes the link is broken, and it may have seen a failure we cannot see.
// If we refused it we would deny that peer the only means it has of repairing
// a connection that is dead in a way we cannot detect - reintroducing, in a
// different form, the very stall this change exists to prevent.
TEST_CASE("A later incoming connection is accepted, so a peer can repair")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    TestNode b("b", "10.0.0.2");
    a.self_id = node_a_id;
    b.self_id = node_b_id;

    // Node A has the lower ID, so it is the node which would otherwise defend
    // its own outgoing connection and refuse B's.
    REQUIRE(node_a_id < node_b_id);

    // Treat any existing outgoing connection as already settled, so B's
    // connection is a repair attempt rather than part of a race.
    a.connections->set_simultaneous_connect_window(
      std::chrono::milliseconds(0));

    a.learn_address(node_b_id, b.host, b.port);
    b.learn_address(node_a_id, a.host, a.port);
    a.drain_to_host();
    b.drain_to_host();

    const auto payload = make_pre_vote();

    // A dials B and the connection settles.
    a.send_to(node_b_id, payload);
    a.drain_to_host();
    complete_connects();
    pump();
    b.drain_to_enclave();
    REQUIRE(b.received > 0);

    // B observes that connection fail, but A does not - an asymmetric failure,
    // which is the case that matters here. B drops its side; A is left holding
    // an outgoing connection it still believes is fine, but whose far end is
    // gone and whose writes now vanish.
    mock_net.deliver_close = false;
    auto* b_listener = mock_net.listeners.at(MockNet::key(b.host, b.port));
    auto* b_side = last_accepted_by(b_listener);
    REQUIRE(b_side != nullptr);
    b_side->behaviour->on_disconnect();

    // B now has no connection to A, so sending makes it dial A. A must accept
    // that connection, because it is B's only way to repair the link.
    const auto a_before = a.received;
    b.send_to(node_a_id, payload);
    b.drain_to_host();
    complete_connects();
    pump();
    a.drain_to_enclave();

    CHECK(a.received > a_before);
  }

  net = nullptr;
}

// The host reads the entries an AppendEntries names from the ledger when it
// frames the message. Those appends are submitted before the send, and the
// frame must carry exactly (prev_idx, idx].
TEST_CASE("AppendEntries frames carry exactly the ledger entries they name")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    TestNode b("b", "10.0.0.2");
    a.self_id = node_a_id;
    b.self_id = node_b_id;

    a.learn_address(node_b_id, b.host, b.port);

    std::vector<std::vector<uint8_t>> entries;
    for (uint8_t i = 1; i <= 4; ++i)
    {
      entries.push_back(make_ledger_entry(i, 8 * i));
      auto entry = entries.back();
      REQUIRE(a.ledger_subsystem->append(std::move(entry), true));
    }

    // Queued behind the appends, and only run once they have been applied
    const auto ae = make_append_entries(1, 3);
    a.send_to(node_b_id, ae);
    a.drain_to_host();
    complete_connects();
    pump();

    REQUIRE(b.inbound->frames.size() == 1);
    const auto& frame = b.inbound->frames[0];
    REQUIRE(frame.type == ccf::NodeMsgType::consensus_msg);
    REQUIRE(frame.from == ccf::NodeId(node_a_id));

    std::vector<uint8_t> expected = ae;
    expected.insert(expected.end(), entries[1].begin(), entries[1].end());
    expected.insert(expected.end(), entries[2].begin(), entries[2].end());
    REQUIRE(frame.payload == expected);
  }

  net = nullptr;
}

TEST_CASE("Sends to a peer arrive in order, including across a close")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    TestNode b("b", "10.0.0.2");
    a.self_id = node_a_id;
    b.self_id = node_b_id;

    a.learn_address(node_b_id, b.host, b.port);
    auto message = [](uint8_t i) {
      auto m = make_pre_vote();
      m.back() = i;
      return m;
    };

    a.send_to(node_b_id, message(1));
    a.send_to(node_b_id, message(2));
    a.drain_to_host();
    complete_connects();
    pump();
    REQUIRE(b.inbound->frames.size() == 2);
    REQUIRE(mock_net.pending_connects.empty());

    // Close is applied after the sends before it, and a later send opens a
    // fresh connection using the retained address
    a.send_to(node_b_id, message(3));
    a.connections->close(node_b_id);
    a.send_to(node_b_id, message(4));
    a.drain_to_host();
    REQUIRE(mock_net.pending_connects.size() == 1);
    complete_connects();
    pump();

    REQUIRE(b.inbound->frames.size() == 4);
    for (uint8_t i = 0; i < 4; ++i)
    {
      REQUIRE(b.inbound->frames[i].payload == message(i + 1));
    }
  }

  net = nullptr;
}

TEST_CASE("Sends to an unknown peer are dropped")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    a.self_id = node_a_id;

    a.send_to(node_b_id, make_pre_vote());
    a.drain_to_host();
    REQUIRE(mock_net.pending_connects.empty());
  }

  net = nullptr;
}

TEST_CASE("Frames above the size limit close the connection unbuffered")
{
  MockNet mock_net;
  net = &mock_net;

  {
    constexpr size_t max_frame_size = 256;
    TestNode a("a", "10.0.0.1", max_frame_size);
    a.self_id = node_a_id;

    auto raw = connect_raw(a);
    REQUIRE(raw->peer != nullptr);

    // Only the size prefix is sent: the declared size alone is rejected,
    // without waiting for (or buffering) the body
    const uint32_t declared = max_frame_size + 1;
    raw->write(
      sizeof(declared), reinterpret_cast<const uint8_t*>(&declared), {});
    pump();

    REQUIRE(raw->peer == nullptr);
    REQUIRE(a.inbound->frames.empty());

    // A frame at the limit is accepted
    TestNode b("b", "10.0.0.2");
    b.self_id = node_b_id;
    b.learn_address(node_a_id, a.host, a.port);
    const auto header_size =
      sizeof(ccf::NodeMsgType) + sizeof(size_t) + node_b_id.size();
    std::vector<uint8_t> body(max_frame_size - header_size, 0x11);
    b.send_to(node_a_id, body);
    b.drain_to_host();
    complete_connects();
    pump();
    REQUIRE(a.inbound->frames.size() == 1);
    REQUIRE(a.inbound->frames[0].payload == body);
  }

  net = nullptr;
}

TEST_CASE("Malformed frames close the connection")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    a.self_id = node_a_id;

    SUBCASE("Frame too small for its headers")
    {
      auto raw = connect_raw(a);
      std::vector<uint8_t> frame(sizeof(uint32_t) + 4, 0);
      const uint32_t declared = 4;
      std::memcpy(frame.data(), &declared, sizeof(declared));
      raw->write(frame.size(), frame.data(), {});
      pump();
      REQUIRE(raw->peer == nullptr);
    }

    SUBCASE("Sender ID longer than the frame")
    {
      auto raw = connect_raw(a);
      std::vector<uint8_t> frame(
        sizeof(uint32_t) + sizeof(ccf::NodeMsgType) + sizeof(size_t), 0);
      auto* data = frame.data();
      auto size = frame.size();
      serialized::write(data, size, static_cast<uint32_t>(16));
      serialized::write(data, size, ccf::NodeMsgType::consensus_msg);
      serialized::write(data, size, static_cast<size_t>(1 << 20));
      raw->write(frame.size(), frame.data(), {});
      pump();
      REQUIRE(raw->peer == nullptr);
    }

    REQUIRE(a.inbound->frames.empty());
  }

  net = nullptr;
}

TEST_CASE("Frames are dropped until an inbound handler is set")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    TestNode b("b", "10.0.0.2");
    a.self_id = node_a_id;
    b.self_id = node_b_id;
    b.connections->set_inbound_handler(nullptr);

    a.learn_address(node_b_id, b.host, b.port);
    a.send_to(node_b_id, make_pre_vote());
    a.drain_to_host();
    complete_connects();
    pump();
    REQUIRE(b.inbound->frames.empty());

    b.connections->set_inbound_handler(b.inbound);
    a.send_to(node_b_id, make_pre_vote());
    a.drain_to_host();
    pump();
    REQUIRE(b.inbound->frames.size() == 1);
  }

  net = nullptr;
}

// The node retains the transport until process exit, so the host must close
// its sockets explicitly before closing the event loop.
TEST_CASE("Shutdown closes every socket and ignores later sends")
{
  MockNet mock_net;
  net = &mock_net;

  {
    TestNode a("a", "10.0.0.1");
    TestNode b("b", "10.0.0.2");
    a.self_id = node_a_id;
    b.self_id = node_b_id;

    a.learn_address(node_b_id, b.host, b.port);
    a.send_to(node_b_id, make_pre_vote());
    a.drain_to_host();
    complete_connects();
    pump();
    REQUIRE(b.inbound->frames.size() == 1);

    auto* a_listener = mock_net.listeners.at(MockNet::key(a.host, a.port));
    const auto live_before = mock_net.live_sockets.size();

    // Keeping another owner alive, as the enclave does
    auto retained = a.connections;
    a.connections->shutdown();

    // A's listener and outgoing socket are gone, and B saw the close
    REQUIRE(mock_net.live_sockets.count(a_listener) == 0);
    REQUIRE(mock_net.live_sockets.size() == live_before - 3);

    a.send_to(node_b_id, make_pre_vote());
    a.drain_to_host();
    REQUIRE(mock_net.pending_connects.empty());
    pump();
    REQUIRE(b.inbound->frames.size() == 1);
  }

  net = nullptr;
}

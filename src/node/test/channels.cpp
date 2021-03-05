// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../channels.h"

#include <doctest/doctest.h>
#include <queue>

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

constexpr auto buffer_size = 1024 * 16;

auto in_buffer_1 = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
auto out_buffer_1 = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
ringbuffer::Circuit eio1(in_buffer_1->bd, out_buffer_1->bd);

auto in_buffer_2 = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
auto out_buffer_2 = std::make_unique<ringbuffer::TestBuffer>(buffer_size);
ringbuffer::Circuit eio2(in_buffer_1->bd, out_buffer_2->bd);

auto wf1 = ringbuffer::WriterFactory(eio1);
auto wf2 = ringbuffer::WriterFactory(eio2);

using namespace ccf;

// Use fixed-size messages as channels messages are not length-prefixed since
// the type of the authenticated header is known in advance (e.g. AppendEntries)
static constexpr auto msg_size = 64;
using MsgType = std::array<uint8_t, msg_size>;

static NodeId self = std::string("self");
static NodeId peer = std::string("peer");

template <typename T>
struct NodeOutboundMsg
{
  NodeId from;
  NodeMsgType type;
  T authenticated_hdr;
  std::vector<uint8_t> payload;
};

template <typename T>
auto read_outbound_msgs(ringbuffer::Circuit& circuit)
{
  std::vector<NodeOutboundMsg<T>> msgs;

  circuit.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case node_outbound:
        {
          serialized::read<NodeId::Value>(
            data, size); // Ignore destination node id
          auto msg_type = serialized::read<NodeMsgType>(data, size);
          NodeId from = serialized::read<NodeId::Value>(data, size);
          auto aad = serialized::read<T>(data, size);
          auto payload = serialized::read(data, size, size);
          msgs.push_back(NodeOutboundMsg<T>{from, msg_type, aad, payload});
          break;
        }
        case add_node:
        {
          LOG_DEBUG_FMT("Add node msg!");
          break;
        }
        default:
        {
          LOG_DEBUG_FMT("Outbound message is not expected: {}", m);
          REQUIRE(false);
        }
      }
    });

  return msgs;
}

auto read_node_msgs(ringbuffer::Circuit& circuit)
{
  std::vector<std::tuple<NodeId, std::string, std::string>> add_node_msgs;
  std::vector<NodeId> remove_node_msgs;

  circuit.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case add_node:
        {
          auto [id, hostname, service] =
            ringbuffer::read_message<ccf::add_node>(data, size);
          add_node_msgs.push_back(std::make_tuple(id, hostname, service));

          break;
        }
        case remove_node:
        {
          auto [id] = ringbuffer::read_message<ccf::remove_node>(data, size);
          remove_node_msgs.push_back(id);
          break;
        }
        default:
        {
          LOG_DEBUG_FMT("Outbound message is not expected: {}", m);
          REQUIRE(false);
        }
      }
    });

  return std::make_pair(add_node_msgs, remove_node_msgs);
}

TEST_CASE("Client/Server key exchange")
{
  auto network_kp = crypto::make_key_pair();
  auto channel1 = Channel(wf1, network_kp, self, peer);
  auto channel2 = Channel(wf2, network_kp, peer, self);

  MsgType msg;
  msg.fill(0x42);

  INFO("Trying to tag/verify before channel establishment");
  {
    REQUIRE_FALSE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    REQUIRE_FALSE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));

    // Every send is replaced with a new channel establishment message
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 2);
    REQUIRE(outbound_msgs[0].type == channel_msg);
    REQUIRE(outbound_msgs[1].type == channel_msg);
  }

  INFO("Establish channels");
  {
    auto channel1_signed_public = channel1.get_signed_public();
    auto channel2_signed_public = channel2.get_signed_public();

    REQUIRE(channel1.load_peer_signed_public(
      true, channel2_signed_public.data(), channel2_signed_public.size()));

    // Messages sent before channel was established are flushed
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    REQUIRE(outbound_msgs[0].type == NodeMsgType::consensus_msg);
    REQUIRE(outbound_msgs[0].authenticated_hdr == msg);

    REQUIRE(channel2.load_peer_signed_public(
      true, channel1_signed_public.data(), channel1_signed_public.size()));

    // Second channel had no pending messages
    outbound_msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(outbound_msgs.size() == 0);
  }

  INFO("Protect integrity of message (peer1 -> peer2)");
  {
    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE(channel2.recv_authenticated(
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Protect integrity of message (peer2 -> peer1)");
  {
    REQUIRE(
      channel2.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE(channel1.recv_authenticated(
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Tamper with message");
  {
    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    msg_.payload[0] += 1; // Tamper with message
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE_FALSE(channel2.recv_authenticated(
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Encrypt message (peer1 -> peer2)");
  {
    std::vector<uint8_t> plain_text(128, 0x1);
    REQUIRE(channel1.send(
      NodeMsgType::consensus_msg, {msg.begin(), msg.size()}, plain_text));

    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    auto decrypted = channel2.recv_encrypted(
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_);

    REQUIRE(decrypted.has_value());
    REQUIRE(decrypted.value() == plain_text);
  }

  INFO("Encrypt message (peer2 -> peer1)");
  {
    std::vector<uint8_t> plain_text(128, 0x1);
    REQUIRE(channel2.send(
      NodeMsgType::consensus_msg, {msg.begin(), msg.size()}, plain_text));

    auto outbound_msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    auto decrypted = channel1.recv_encrypted(
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_);

    REQUIRE(decrypted.has_value());
    REQUIRE(decrypted.value() == plain_text);
  }
}

TEST_CASE("Replay and out-of-order")
{
  auto network_kp = crypto::make_key_pair();
  auto channel1 = Channel(wf1, network_kp, self, peer);
  auto channel2 = Channel(wf2, network_kp, peer, self);

  MsgType msg;
  msg.fill(0x42);

  INFO("Establish channels");
  {
    auto channel1_signed_public = channel1.get_signed_public();
    auto channel2_signed_public = channel2.get_signed_public();

    REQUIRE(channel1.load_peer_signed_public(
      true, channel2_signed_public.data(), channel2_signed_public.size()));
    REQUIRE(channel2.load_peer_signed_public(
      true, channel1_signed_public.data(), channel1_signed_public.size()));
  }

  NodeOutboundMsg<MsgType> first_msg, first_msg_copy;

  INFO("Replay same message");
  {
    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    first_msg = outbound_msgs[0];
    REQUIRE(first_msg.from == self);
    auto msg_copy = first_msg;
    first_msg_copy = first_msg;
    const auto* data_ = first_msg.payload.data();
    auto size_ = first_msg.payload.size();
    REQUIRE(first_msg.type == NodeMsgType::consensus_msg);

    REQUIRE(channel2.recv_authenticated(
      {first_msg.authenticated_hdr.begin(), first_msg.authenticated_hdr.size()},
      data_,
      size_));

    // Replay
    data_ = msg_copy.payload.data();
    size_ = msg_copy.payload.size();
    REQUIRE_FALSE(channel2.recv_authenticated(
      {msg_copy.authenticated_hdr.begin(), msg_copy.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Issue more messages and replay old one");
  {
    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    REQUIRE(read_outbound_msgs<MsgType>(eio1).size() == 1);

    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    REQUIRE(read_outbound_msgs<MsgType>(eio1).size() == 1);

    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE(channel2.recv_authenticated(
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));

    const auto* first_msg_data_ = first_msg_copy.payload.data();
    auto first_msg_size_ = first_msg_copy.payload.size();
    REQUIRE_FALSE(channel2.recv_authenticated(
      {first_msg_copy.authenticated_hdr.begin(),
       first_msg_copy.authenticated_hdr.size()},
      first_msg_data_,
      first_msg_size_));
  }
}

TEST_CASE("Host connections")
{
  auto network_kp = crypto::make_key_pair();
  auto channel_manager =
    ChannelManager(wf1, network_kp->private_key_pem(), self);

  INFO("New channel creates host connection");
  {
    channel_manager.create_channel(peer, "hostname", "port");
    auto [add_node_msgs, remove_node_msgs] = read_node_msgs(eio1);
    REQUIRE(add_node_msgs.size() == 1);
    REQUIRE(remove_node_msgs.size() == 0);
    REQUIRE(std::get<0>(add_node_msgs[0]) == peer);
    REQUIRE(std::get<1>(add_node_msgs[0]) == "hostname");
    REQUIRE(std::get<2>(add_node_msgs[0]) == "port");
  }

  INFO("Retrieving unknown channel does not create host connection");
  {
    NodeId unknown_peer_id = std::string("unknown_peer");
    channel_manager.get(unknown_peer_id);
    auto [add_node_msgs, remove_node_msgs] = read_node_msgs(eio1);
    REQUIRE(add_node_msgs.size() == 0);
    REQUIRE(remove_node_msgs.size() == 0);
  }

  INFO("Destroying channel closes host connection");
  {
    channel_manager.destroy_channel(peer);
    auto [add_node_msgs, remove_node_msgs] = read_node_msgs(eio1);
    REQUIRE(add_node_msgs.size() == 0);
    REQUIRE(remove_node_msgs.size() == 1);
  }
}
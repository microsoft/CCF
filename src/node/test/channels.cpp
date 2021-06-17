// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../channels.h"

#include "crypto/verifier.h"
#include "ds/hex.h"
#include "node/entities.h"
#include "node/node_to_node.h"
#include "node/node_types.h"

#include <algorithm>
#include <cstring>
#include <queue>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

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

static constexpr auto default_curve = crypto::CurveID::SECP384R1;

template <typename T>
struct NodeOutboundMsg
{
  NodeId from;
  NodeMsgType type;
  T authenticated_hdr;
  std::vector<uint8_t> payload;

  std::vector<uint8_t> data() const
  {
    std::vector<uint8_t> r;
    r.insert(r.end(), authenticated_hdr.begin(), authenticated_hdr.end());
    r.insert(r.end(), payload.begin(), payload.end());
    return r;
  }

  std::vector<uint8_t> unauthenticated_data() const
  {
    auto r = data();
    auto type_hdr_bytes = std::vector<uint8_t>(r.begin(), r.begin() + 8);
    CBuffer type_hdr(type_hdr_bytes.data(), type_hdr_bytes.size());
    ChannelMsg channel_msg_type =
      serialized::read<ChannelMsg>(type_hdr.p, type_hdr.n);
    auto data = std::vector<uint8_t>(r.begin() + 8, r.end());
    return data;
  }
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
          T aad;
          if (size > sizeof(T))
            aad = serialized::read<T>(data, size);
          auto payload = serialized::read(data, size, size);
          msgs.push_back(NodeOutboundMsg<T>{from, msg_type, aad, payload});
          break;
        }
        case add_node:
        {
          LOG_DEBUG_FMT("Add node msg!");
          break;
        }
        case remove_node:
        {
          LOG_DEBUG_FMT("Remove node msg!");
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

NodeOutboundMsg<MsgType> get_first(
  ringbuffer::Circuit& circuit, NodeMsgType msg_type)
{
  auto outbound_msgs = read_outbound_msgs<MsgType>(circuit);
  REQUIRE(outbound_msgs.size() == 1);
  auto msg = outbound_msgs[0];
  const auto* data_ = msg.payload.data();
  auto size_ = msg.payload.size();
  REQUIRE(msg.type == msg_type);
  return msg;
}

TEST_CASE("Client/Server key exchange")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto network_cert = network_kp->self_sign("CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_csr = channel1_kp->create_csr("CN=Node1");
  auto channel1_cert = network_kp->sign_csr(network_cert, channel1_csr, {});

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_csr = channel2_kp->create_csr("CN=Node2");
  auto channel2_cert = network_kp->sign_csr(network_cert, channel2_csr, {});

  auto v = crypto::make_verifier(channel1_cert);
  REQUIRE(v->verify_certificate({&network_cert}));
  v = crypto::make_verifier(channel2_cert);
  REQUIRE(v->verify_certificate({&network_cert}));

  REQUIRE(!make_verifier(channel2_cert)->is_self_signed());

  auto channel1 =
    Channel(wf1, network_cert, channel1_kp, channel1_cert, self, peer);
  auto channel2 =
    Channel(wf2, network_cert, channel2_kp, channel2_cert, peer, self);

  MsgType msg;
  msg.fill(0x42);

  INFO("Trying to tag/verify before channel establishment");
  {
    // Try sending on channel1 twice
    REQUIRE_FALSE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    REQUIRE_FALSE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
  }

  std::vector<uint8_t> channel1_signed_key_share;

  INFO("Extract key share, signature, certificate from messages");
  {
    // Every send has been replaced with a new channel establishment message
    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].type == channel_msg);
    REQUIRE(msgs[1].type == channel_msg);
    REQUIRE(read_outbound_msgs<MsgType>(eio2).size() == 0);

#ifndef DETERMINISTIC_ECDSA
    // Signing twice should have produced different signatures
    REQUIRE(msgs[0].unauthenticated_data() != msgs[1].unauthenticated_data());
#endif

    channel1_signed_key_share = msgs[0].unauthenticated_data();
  }

  INFO("Load peer key share and check signature");
  {
    REQUIRE(channel2.consume_initiator_key_share(channel1_signed_key_share));
    REQUIRE(channel1.get_status() == INITIATED);
    REQUIRE(channel2.get_status() == WAITING_FOR_FINAL);
  }

  std::vector<uint8_t> channel2_signed_key_share;

  INFO("Extract responder signature over both key shares from messages");
  {
    // Messages sent before channel was established are flushed, so only 1 each.
    auto msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    channel2_signed_key_share = msgs[0].unauthenticated_data();
    REQUIRE(read_outbound_msgs<MsgType>(eio1).size() == 0);
  }

  INFO("Load responder key share and check signature");
  {
    REQUIRE(channel1.consume_responder_key_share(channel2_signed_key_share));
    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == WAITING_FOR_FINAL);
  }

  std::vector<uint8_t> initiator_signature;
  NodeOutboundMsg<MsgType> queued_msg;

  INFO("Extract responder signature from message");
  {
    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].type == channel_msg);
    REQUIRE(msgs[1].type == consensus_msg);
    initiator_signature = msgs[0].unauthenticated_data();

    auto md = msgs[1].data();
    REQUIRE(md.size() == msg.size() + sizeof(GcmHdr));
    REQUIRE(memcmp(md.data(), msg.data(), msg.size()) == 0);

    queued_msg = msgs[1]; // save for later
  }

  INFO("Cross-check responder signature and establish channels");
  {
    REQUIRE(channel2.check_peer_key_share_signature(initiator_signature));
    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == ESTABLISHED);
  }

  INFO("Receive queued message");
  {
    // Receive the queued message to ensure the sequence numbers are contiguous.
    auto hdr = queued_msg.authenticated_hdr;
    auto payload = queued_msg.payload;
    const auto* data = payload.data();
    auto size = payload.size();
    channel2.recv_authenticated({hdr.begin(), hdr.size()}, data, size);
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
  auto network_kp = crypto::make_key_pair(default_curve);
  auto network_cert = network_kp->self_sign("CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_csr = channel1_kp->create_csr("CN=Node1");
  auto channel1_cert = network_kp->sign_csr(network_cert, channel1_csr, {});

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_csr = channel2_kp->create_csr("CN=Node2");
  auto channel2_cert = network_kp->sign_csr(network_cert, channel2_csr, {});

  auto channel1 =
    Channel(wf1, network_cert, channel1_kp, channel1_cert, self, peer);
  auto channel2 =
    Channel(wf2, network_cert, channel2_kp, channel2_cert, peer, self);

  MsgType msg;
  msg.fill(0x42);

  INFO("Establish channels");
  {
    channel1.initiate();

    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    auto channel1_signed_key_share = msgs[0].unauthenticated_data();

    REQUIRE(channel2.consume_initiator_key_share(channel1_signed_key_share));

    msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    auto channel2_signed_key_share = msgs[0].unauthenticated_data();
    REQUIRE(channel1.consume_responder_key_share(channel2_signed_key_share));

    msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    auto initiator_signature = msgs[0].unauthenticated_data();

    REQUIRE(channel2.check_peer_key_share_signature(initiator_signature));
    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == ESTABLISHED);
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

  INFO("Trigger new key exchange");
  {
    auto n = read_outbound_msgs<MsgType>(eio1).size() +
      read_outbound_msgs<MsgType>(eio2).size();
    REQUIRE(n == 0);

    channel1.initiate();
    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == ESTABLISHED);

    auto fst = get_first(eio1, NodeMsgType::channel_msg);
    REQUIRE(
      channel2.consume_initiator_key_share(fst.unauthenticated_data(), true));
    REQUIRE(channel2.get_status() == ESTABLISHED);
    fst = get_first(eio2, NodeMsgType::channel_msg);
    REQUIRE(channel1.consume_responder_key_share(fst.unauthenticated_data()));
    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 1);
    REQUIRE(
      channel2.check_peer_key_share_signature(msgs[0].unauthenticated_data()));
    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == ESTABLISHED);

    REQUIRE(
      channel1.send(NodeMsgType::consensus_msg, {msg.begin(), msg.size()}));
    fst = get_first(eio1, NodeMsgType::consensus_msg);
  }
}

TEST_CASE("Interrupted key exchange")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto network_cert = network_kp->self_sign("CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_csr = channel1_kp->create_csr("CN=Node1");
  auto channel1_cert = network_kp->sign_csr(network_cert, channel1_csr, {});

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_csr = channel2_kp->create_csr("CN=Node2");
  auto channel2_cert = network_kp->sign_csr(network_cert, channel2_csr, {});

  auto channel1 =
    Channel(wf1, network_cert, channel1_kp, channel1_cert, self, peer);
  auto channel2 =
    Channel(wf2, network_cert, channel2_kp, channel2_cert, peer, self);

  std::vector<uint8_t> msg;
  msg.push_back(0x42);
  msg.push_back(0x1);
  msg.push_back(0x10);
  msg.push_back(0x0);
  msg.push_back(0x1);
  msg.push_back(0x42);

  enum class DropStage
  {
    InitiationMessage,
    ResponseMessage,
    FinalMessage,
    NoDrops,
  };
  for (const auto drop_stage : {DropStage::InitiationMessage,
                                DropStage::ResponseMessage,
                                DropStage::FinalMessage,
                                DropStage::NoDrops})
  {
    INFO("Drop stage is ", (size_t)drop_stage);

    channel1.reset();
    channel2.reset();
    REQUIRE(channel1.get_status() == INACTIVE);
    REQUIRE(channel2.get_status() == INACTIVE);

    channel1.initiate();

    REQUIRE(channel1.get_status() == INITIATED);
    REQUIRE(channel2.get_status() == INACTIVE);

    auto initiator_key_share_msg = get_first(eio1, NodeMsgType::channel_msg);
    if (drop_stage > DropStage::InitiationMessage)
    {
      REQUIRE(channel2.consume_initiator_key_share(
        initiator_key_share_msg.unauthenticated_data()));

      REQUIRE(channel1.get_status() == INITIATED);
      REQUIRE(channel2.get_status() == WAITING_FOR_FINAL);

      auto responder_key_share_msg = get_first(eio2, NodeMsgType::channel_msg);
      if (drop_stage > DropStage::ResponseMessage)
      {
        REQUIRE(channel1.consume_responder_key_share(
          responder_key_share_msg.unauthenticated_data()));

        REQUIRE(channel1.get_status() == ESTABLISHED);
        REQUIRE(channel2.get_status() == WAITING_FOR_FINAL);

        auto initiator_key_exchange_final_msg =
          get_first(eio1, NodeMsgType::channel_msg);
        if (drop_stage > DropStage::FinalMessage)
        {
          REQUIRE(channel2.check_peer_key_share_signature(
            initiator_key_exchange_final_msg.unauthenticated_data()));

          REQUIRE(channel1.get_status() == ESTABLISHED);
          REQUIRE(channel2.get_status() == ESTABLISHED);
        }
      }
    }

    INFO("Later attempts to connect should succeed");
    {
      SUBCASE("Node 1 attempts to connect")
      {
        std::cout << "Node 1 attempts to connect" << std::endl;
        channel1.initiate();

        REQUIRE(channel2.consume_initiator_key_share(
          get_first(eio1, NodeMsgType::channel_msg).unauthenticated_data()));
        REQUIRE(channel1.consume_responder_key_share(
          get_first(eio2, NodeMsgType::channel_msg).unauthenticated_data()));
        REQUIRE(channel2.check_peer_key_share_signature(
          get_first(eio1, NodeMsgType::channel_msg).unauthenticated_data()));

        REQUIRE(channel1.get_status() == ESTABLISHED);
        REQUIRE(channel2.get_status() == ESTABLISHED);
      }

      SUBCASE("Node 2 attempts to connect")
      {
        std::cout << "Node 2 attempts to connect" << std::endl;
        channel2.initiate();

        REQUIRE(channel1.consume_initiator_key_share(
          get_first(eio2, NodeMsgType::channel_msg).unauthenticated_data()));
        REQUIRE(channel2.consume_responder_key_share(
          get_first(eio1, NodeMsgType::channel_msg).unauthenticated_data()));
        REQUIRE(channel1.check_peer_key_share_signature(
          get_first(eio2, NodeMsgType::channel_msg).unauthenticated_data()));

        REQUIRE(channel1.get_status() == ESTABLISHED);
        REQUIRE(channel2.get_status() == ESTABLISHED);
      }

      REQUIRE(
        channel1.send(NodeMsgType::consensus_msg, {msg.data(), msg.size()}));
      auto msg1 = get_first(eio1, NodeMsgType::consensus_msg);
      auto decrypted1 = channel2.recv_encrypted(
        {msg1.authenticated_hdr.data(), msg1.authenticated_hdr.size()},
        msg1.payload.data(),
        msg1.payload.size());
      REQUIRE(decrypted1.has_value());
      REQUIRE(decrypted1.value() == msg);

      REQUIRE(
        channel2.send(NodeMsgType::consensus_msg, {msg.data(), msg.size()}));
      auto msg2 = get_first(eio2, NodeMsgType::consensus_msg);
      auto decrypted2 = channel1.recv_encrypted(
        {msg2.authenticated_hdr.data(), msg2.authenticated_hdr.size()},
        msg2.payload.data(),
        msg2.payload.size());
      REQUIRE(decrypted2.has_value());
      REQUIRE(decrypted2.value() == msg);
    }
  }
}

TEST_CASE("Host connections")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto network_cert = network_kp->self_sign("CN=Network");
  auto channel_kp = crypto::make_key_pair(default_curve);
  auto channel_cert = channel_kp->self_sign("CN=Node");
  auto channel_manager =
    ChannelManager(wf1, network_cert, channel_kp, channel_cert, self);

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

TEST_CASE("Concurrent key exchange init")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto network_cert = network_kp->self_sign("CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_csr = channel1_kp->create_csr("CN=Node1");
  auto channel1_cert = network_kp->sign_csr(network_cert, channel1_csr, {});

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_csr = channel2_kp->create_csr("CN=Node2");
  auto channel2_cert = network_kp->sign_csr(network_cert, channel2_csr, {});

  auto channel1 =
    Channel(wf1, network_cert, channel1_kp, channel1_cert, self, peer);
  auto channel2 =
    Channel(wf2, network_cert, channel2_kp, channel2_cert, peer, self);

  MsgType msg;
  msg.fill(0x42);

  INFO("Channel 1 wins");
  {
    channel1.initiate();
    channel2.initiate();

    REQUIRE(channel1.get_status() == INITIATED);
    REQUIRE(channel2.get_status() == INITIATED);

    auto fst1 = get_first(eio1, NodeMsgType::channel_msg);
    auto fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(
      channel1.consume_initiator_key_share(fst2.unauthenticated_data(), true));
    REQUIRE(
      channel2.consume_initiator_key_share(fst1.unauthenticated_data(), false));

    REQUIRE(channel1.get_status() == WAITING_FOR_FINAL);
    REQUIRE(channel2.get_status() == INITIATED);

    fst1 = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channel2.consume_responder_key_share(fst1.unauthenticated_data()));

    fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(
      channel1.check_peer_key_share_signature(fst2.unauthenticated_data()));

    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == ESTABLISHED);
  }

  channel1.reset();
  channel2.reset();

  INFO("Channel 2 wins");
  {
    channel1.initiate();
    channel2.initiate();

    REQUIRE(channel1.get_status() == INITIATED);
    REQUIRE(channel2.get_status() == INITIATED);

    auto fst1 = get_first(eio1, NodeMsgType::channel_msg);
    auto fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(
      channel1.consume_initiator_key_share(fst2.unauthenticated_data(), false));
    REQUIRE(
      channel2.consume_initiator_key_share(fst1.unauthenticated_data(), true));

    REQUIRE(channel1.get_status() == INITIATED);
    REQUIRE(channel2.get_status() == WAITING_FOR_FINAL);

    fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channel1.consume_responder_key_share(fst2.unauthenticated_data()));

    fst1 = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(
      channel2.check_peer_key_share_signature(fst1.unauthenticated_data()));

    REQUIRE(channel1.get_status() == ESTABLISHED);
    REQUIRE(channel2.get_status() == ESTABLISHED);
  }
}

static std::vector<NodeOutboundMsg<MsgType>> get_all_msgs(
  std::set<ringbuffer::Circuit*> eios)
{
  std::vector<NodeOutboundMsg<MsgType>> res;
  for (auto& eio : eios)
  {
    auto msgs = read_outbound_msgs<MsgType>(*eio);
    res.insert(res.end(), msgs.begin(), msgs.end());
  }
  return res;
}

struct CurveChoices
{
  crypto::CurveID network;
  crypto::CurveID node_1;
  crypto::CurveID node_2;
};

TEST_CASE("Full NodeToNode test")
{
  constexpr auto all_256 = CurveChoices{crypto::CurveID::SECP256R1,
                                        crypto::CurveID::SECP256R1,
                                        crypto::CurveID::SECP256R1};
  constexpr auto all_384 = CurveChoices{crypto::CurveID::SECP384R1,
                                        crypto::CurveID::SECP384R1,
                                        crypto::CurveID::SECP384R1};
  // One node on a different curve
  constexpr auto mixed_0 = CurveChoices{crypto::CurveID::SECP256R1,
                                        crypto::CurveID::SECP256R1,
                                        crypto::CurveID::SECP384R1};
  // Both nodes on a different curve
  constexpr auto mixed_1 = CurveChoices{crypto::CurveID::SECP384R1,
                                        crypto::CurveID::SECP256R1,
                                        crypto::CurveID::SECP256R1};

  size_t i = 0;
  for (const auto& curves : {all_256, all_384, mixed_0, mixed_1})
  {
    LOG_DEBUG_FMT("Iteration: {}", i++);

    auto network_kp = crypto::make_key_pair(curves.network);
    auto network_cert = network_kp->self_sign("CN=Network");

    auto ni1 = std::string("N1");
    auto channel1_kp = crypto::make_key_pair(curves.node_1);
    auto channel1_csr = channel1_kp->create_csr("CN=Node1");
    auto channel1_cert = network_kp->sign_csr(network_cert, channel1_csr, {});

    auto ni2 = std::string("N2");
    auto channel2_kp = crypto::make_key_pair(curves.node_2);
    auto channel2_csr = channel2_kp->create_csr("CN=Node2");
    auto channel2_cert = network_kp->sign_csr(network_cert, channel2_csr, {});

    size_t message_limit = 32;

    MsgType msg;
    msg.fill(0x42);

    INFO("Set up channels");
    NodeToNodeImpl n2n1(wf1), n2n2(wf2);

    n2n1.initialize(ni1, network_cert, channel1_kp, channel1_cert);
    n2n1.create_channel(ni2, "", "", message_limit);
    n2n2.initialize(ni2, network_cert, channel2_kp, channel2_cert);
    n2n2.create_channel(ni1, "", "", message_limit);

    srand(0); // keep it deterministic

    INFO("Send/receive a number of messages");
    {
      size_t desired_rollovers = 5;
      size_t actual_rollovers = 0;

      for (size_t i = 0; i < message_limit * desired_rollovers; i++)
      {
        if (rand() % 2 == 0)
        {
          n2n1.send_authenticated(
            ni2, NodeMsgType::consensus_msg, msg.data(), msg.size());
        }
        else
        {
          n2n2.send_authenticated(
            ni1, NodeMsgType::consensus_msg, msg.data(), msg.size());
        }

        auto msgs = get_all_msgs({&eio1, &eio2});
        do
        {
          for (auto msg : msgs)
          {
            auto& n2n = (msg.from == ni2) ? n2n1 : n2n2;

            switch (msg.type)
            {
              case NodeMsgType::channel_msg:
              {
                n2n.recv_message(msg.from, msg.data());

                auto d = msg.data();
                const uint8_t* data = d.data();
                size_t sz = d.size();
                auto type = serialized::read<ChannelMsg>(data, sz);
                if (type == key_exchange_final)
                  actual_rollovers++;
                break;
              }
              case NodeMsgType::consensus_msg:
              {
                auto hdr = msg.authenticated_hdr;
                const auto* data = msg.payload.data();
                auto size = msg.payload.size();

                REQUIRE(n2n.recv_authenticated(
                  msg.from, {hdr.data(), hdr.size()}, data, size));
                break;
              }
              default:
                REQUIRE(false);
            }
          }

          msgs = get_all_msgs({&eio1, &eio2});
        } while (msgs.size() > 0);
      }

      REQUIRE(actual_rollovers >= desired_rollovers);
    }
  }
}
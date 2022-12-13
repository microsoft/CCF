// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../channels.h"

#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "crypto/certs.h"
#include "crypto/openssl/x509_time.h"
#include "ds/ring_buffer.h"
#include "node/node_to_node_channel_manager.h"
#include "node/node_types.h"

#include <algorithm>
#include <cstring>
#include <queue>
#include <random>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

namespace ccf
{
  std::atomic<long long>* host_time_us = nullptr;
  std::chrono::microseconds last_value(0);
}

namespace ccf
{
  std::chrono::microseconds Channel::min_gap_between_initiation_attempts(0);
}

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

constexpr auto buffer_size = 1024 * 8;

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

static NodeId nid1 = std::string("nid1");
static NodeId nid2 = std::string("nid2");

static constexpr auto default_curve = crypto::CurveID::SECP384R1;

static std::pair<std::string, size_t> make_validity_pair(bool expired)
{
  using namespace std::literals;
  const auto now = std::chrono::system_clock::now();
  constexpr size_t validity_days = 365;
  if (expired)
  {
    return std::make_pair(
      ds::to_x509_time_string(now - std::chrono::days(2 * validity_days)),
      validity_days);
  }
  else
  {
    return std::make_pair(ds::to_x509_time_string(now - 24h), validity_days);
  }
}

static crypto::Pem generate_self_signed_cert(
  const crypto::KeyPairPtr& kp, const std::string& name, bool expired = false)
{
  const auto [valid_from, validity_days] = make_validity_pair(expired);

  return crypto::create_self_signed_cert(
    kp, name, {}, valid_from, validity_days);
}

static crypto::Pem generate_endorsed_cert(
  const crypto::KeyPairPtr& kp,
  const std::string& name,
  const crypto::KeyPairPtr& issuer_kp,
  const crypto::Pem& issuer_cert,
  bool expired = false)
{
  const auto [valid_from, validity_days] = make_validity_pair(expired);

  return crypto::create_endorsed_cert(
    kp,
    name,
    {},
    valid_from,
    validity_days,
    issuer_kp->private_key_pem(),
    issuer_cert);
}

template <typename T>
struct NodeOutboundMsg
{
  NodeId from;
  NodeId to;
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
    static_assert(sizeof(ChannelMsg) == 8);
    size_t hdr_size = sizeof(ChannelMsg);
    ChannelMsg channel_msg_type =
      serialized::read<ChannelMsg>(r.data(), hdr_size);
    auto data = std::vector<uint8_t>(r.begin() + sizeof(ChannelMsg), r.end());
    return data;
  }
};

template <typename T>
auto read_outbound_msgs(ringbuffer::Circuit& circuit)
{
  std::vector<NodeOutboundMsg<T>> msgs;

  // A call to ringbuffer::Reader::read() may return 0 when there are still
  // messages to read, when it reaches the end of the buffer. The next call to
  // read() will correctly start at the beginning of the buffer and read these
  // messages. So to make sure we always get the messages we expect in this
  // test, read twice.
  for (size_t i = 0; i < 2; ++i)
  {
    circuit.read_from_inside().read(
      -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
        switch (m)
        {
          case node_outbound:
          {
            NodeId to = serialized::read<NodeId::Value>(data, size);
            auto msg_type = serialized::read<NodeMsgType>(data, size);
            NodeId from = serialized::read<NodeId::Value>(data, size);
            T aad;
            if (size > sizeof(T))
              aad = serialized::read<T>(data, size);
            auto payload = serialized::read(data, size, size);
            msgs.push_back(
              NodeOutboundMsg<T>{from, to, msg_type, aad, payload});
            break;
          }
          case associate_node_address:
          case close_node_outbound:
          {
            // Ignored
            break;
          }
          default:
          {
            LOG_INFO_FMT("Outbound message is not expected: {}", m);
            REQUIRE(false);
          }
        }
      });
  }

  return msgs;
}

auto read_node_msgs(ringbuffer::Circuit& circuit)
{
  std::vector<std::tuple<NodeId, std::string, std::string>> add_node_msgs;

  circuit.read_from_inside().read(
    -1, [&](ringbuffer::Message m, const uint8_t* data, size_t size) {
      switch (m)
      {
        case ccf::associate_node_address:
        {
          auto [id, hostname, service] =
            ringbuffer::read_message<ccf::associate_node_address>(data, size);
          add_node_msgs.push_back(std::make_tuple(id, hostname, service));

          break;
        }
        default:
        {
          LOG_INFO_FMT("Outbound message is not expected: {}", m);
          REQUIRE(false);
        }
      }
    });

  return add_node_msgs;
}

NodeOutboundMsg<MsgType> get_first(
  ringbuffer::Circuit& circuit, NodeMsgType msg_type)
{
  auto outbound_msgs = read_outbound_msgs<MsgType>(circuit);
  REQUIRE(outbound_msgs.size() >= 1);
  auto msg = outbound_msgs[0];
  const auto* data_ = msg.payload.data();
  auto size_ = msg.payload.size();
  REQUIRE(msg.type == msg_type);
  return msg;
}

TEST_CASE("Client/Server key exchange")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node2", network_kp, service_cert);

  auto v = crypto::make_verifier(channel1_cert);
  REQUIRE(v->verify_certificate({&service_cert}));
  v = crypto::make_verifier(channel2_cert);
  REQUIRE(v->verify_certificate({&service_cert}));

  REQUIRE(!make_verifier(channel2_cert)->is_self_signed());

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);
  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);

  MsgType msg;
  msg.fill(0x42);

  INFO("Trying to tag/verify before channel establishment");
  {
    // Try sending on channel1 twice
    REQUIRE_FALSE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    REQUIRE_FALSE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
  }

  std::vector<uint8_t> channel1_signed_key_share;

  INFO("Extract key share, signature, certificate from messages");
  {
    // Attempting to send has produced a new channel establishment message
    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].type == channel_msg);
    REQUIRE(msgs[1].type == channel_msg);
    REQUIRE(read_outbound_msgs<MsgType>(eio2).size() == 0);

#ifndef DETERMINISTIC_ECDSA
    // Signing twice should have produced different signatures
    REQUIRE(msgs[0].data() != msgs[1].data());
#endif

    // Use the latter attempt - it is the state channel1 is working with
    channel1_signed_key_share = msgs[1].data();
  }

  INFO("Load peer key share and check signature");
  {
    REQUIRE(channels2.recv_channel_message(
      nid1, std::move(channel1_signed_key_share)));
    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);
  }

  std::vector<uint8_t> channel2_signed_key_share;

  INFO("Extract responder signature over both key shares from messages");
  {
    // Messages sent before channel was established are flushed, so only 1 each.
    auto msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    channel2_signed_key_share = msgs[0].data();
    REQUIRE(read_outbound_msgs<MsgType>(eio1).size() == 0);
  }

  INFO("Load responder key share and check signature");
  {
    REQUIRE(channels1.recv_channel_message(
      nid2, std::move(channel2_signed_key_share)));
    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);
  }

  std::vector<uint8_t> initiator_signature;
  NodeOutboundMsg<MsgType> queued_msg;

  INFO("Extract responder signature from message");
  {
    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].type == channel_msg);
    REQUIRE(msgs[1].type == consensus_msg);
    initiator_signature = msgs[0].data();

    auto md = msgs[1].data();
    REQUIRE(md.size() == msg.size() + GcmHdr::serialised_size());
    REQUIRE(memcmp(md.data(), msg.data(), msg.size()) == 0);

    queued_msg = msgs[1]; // save for later
  }

  INFO("Cross-check responder signature and establish channels");
  {
    REQUIRE(
      channels2.recv_channel_message(nid1, std::move(initiator_signature)));
    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);
  }

  INFO("Receive queued message");
  {
    // Receive the queued message to ensure the sequence numbers are contiguous.
    auto hdr = queued_msg.authenticated_hdr;
    auto payload = queued_msg.payload;
    const auto* data = payload.data();
    auto size = payload.size();
    REQUIRE(channels2.recv_authenticated(
      nid1, {hdr.begin(), hdr.size()}, data, size));
  }

  INFO("Protect integrity of message (peer1 -> peer2)");
  {
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE(channels2.recv_authenticated(
      nid1,
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Protect integrity of message (peer2 -> peer1)");
  {
    REQUIRE(channels2.send_authenticated(
      nid1, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE(channels1.recv_authenticated(
      nid2,
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Tamper with message");
  {
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    msg_.payload[0] += 1; // Tamper with message
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE_FALSE(channels2.recv_authenticated(
      nid1,
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Encrypt message (peer1 -> peer2)");
  {
    std::vector<uint8_t> plain_text(128, 0x1);
    REQUIRE(channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {msg.begin(), msg.size()}, plain_text));

    auto msg_ = get_first(eio1, NodeMsgType::consensus_msg);
    auto decrypted = channels2.recv_encrypted(
      nid1,
      {msg_.authenticated_hdr.data(), msg_.authenticated_hdr.size()},
      msg_.payload.data(),
      msg_.payload.size());

    REQUIRE(decrypted == plain_text);
  }

  INFO("Encrypt message (peer2 -> peer1)");
  {
    std::vector<uint8_t> plain_text(128, 0x2);
    REQUIRE(channels2.send_encrypted(
      nid1, NodeMsgType::consensus_msg, {msg.begin(), msg.size()}, plain_text));

    auto msg_ = get_first(eio2, NodeMsgType::consensus_msg);
    auto decrypted = channels1.recv_encrypted(
      nid2,
      {msg_.authenticated_hdr.data(), msg_.authenticated_hdr.size()},
      msg_.payload.data(),
      msg_.payload.size());

    REQUIRE(decrypted == plain_text);
  }
}

TEST_CASE("Replay and out-of-order")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node2", network_kp, service_cert);

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);
  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);

  MsgType msg;
  msg.fill(0x42);

  INFO("Establish channels");
  {
    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());

    auto msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    auto channel1_signed_key_share = msgs[0].data();

    REQUIRE(channels2.recv_channel_message(
      nid1, std::move(channel1_signed_key_share)));

    msgs = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(msgs.size() == 1);
    REQUIRE(msgs[0].type == channel_msg);
    auto channel2_signed_key_share = msgs[0].data();
    REQUIRE(channels1.recv_channel_message(
      nid2, std::move(channel2_signed_key_share)));

    msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(msgs.size() == 2);
    REQUIRE(msgs[0].type == channel_msg);
    auto initiator_signature = msgs[0].data();

    REQUIRE(
      channels2.recv_channel_message(nid1, std::move(initiator_signature)));
    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

    REQUIRE(msgs[1].type == consensus_msg);

    const auto* payload_data = msgs[1].payload.data();
    auto payload_size = msgs[1].payload.size();
    REQUIRE(channels2.recv_authenticated(
      nid1,
      {msgs[1].authenticated_hdr.data(), msgs[1].authenticated_hdr.size()},
      payload_data,
      payload_size));
  }

  NodeOutboundMsg<MsgType> first_msg, first_msg_copy;

  INFO("Replay same message");
  {
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    first_msg = outbound_msgs[0];
    REQUIRE(first_msg.from == nid1);
    REQUIRE(first_msg.to == nid2);
    auto msg_copy = first_msg;
    first_msg_copy = first_msg;
    const auto* data_ = first_msg.payload.data();
    auto size_ = first_msg.payload.size();
    REQUIRE(first_msg.type == NodeMsgType::consensus_msg);

    REQUIRE(channels2.recv_authenticated(
      nid1,
      {first_msg.authenticated_hdr.begin(), first_msg.authenticated_hdr.size()},
      data_,
      size_));

    // Replay
    data_ = msg_copy.payload.data();
    size_ = msg_copy.payload.size();
    REQUIRE_FALSE(channels2.recv_authenticated(
      nid1,
      {msg_copy.authenticated_hdr.begin(), msg_copy.authenticated_hdr.size()},
      data_,
      size_));
  }

  INFO("Issue more messages and replay old one");
  {
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    REQUIRE(read_outbound_msgs<MsgType>(eio1).size() == 1);

    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    REQUIRE(read_outbound_msgs<MsgType>(eio1).size() == 1);

    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    auto outbound_msgs = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound_msgs.size() == 1);
    auto msg_ = outbound_msgs[0];
    const auto* data_ = msg_.payload.data();
    auto size_ = msg_.payload.size();
    REQUIRE(msg_.type == NodeMsgType::consensus_msg);

    REQUIRE(channels2.recv_authenticated(
      nid1,
      {msg_.authenticated_hdr.begin(), msg_.authenticated_hdr.size()},
      data_,
      size_));

    const auto* first_msg_data_ = first_msg_copy.payload.data();
    auto first_msg_size_ = first_msg_copy.payload.size();
    REQUIRE_FALSE(channels2.recv_authenticated(
      nid1,
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

    channels1.close_channel(nid2);
    REQUIRE(channels1.get_status(nid2) == INACTIVE);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());
    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

    REQUIRE(channels2.recv_channel_message(
      nid1, get_first(eio1, NodeMsgType::channel_msg).data()));
    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);

    REQUIRE(channels1.recv_channel_message(
      nid2, get_first(eio2, NodeMsgType::channel_msg).data()));
    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);

    auto messages_1to2 = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(messages_1to2.size() == 2);
    REQUIRE(messages_1to2[0].type == NodeMsgType::channel_msg);
    REQUIRE(channels2.recv_channel_message(nid1, messages_1to2[0].data()));
    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

    REQUIRE(messages_1to2[1].type == NodeMsgType::consensus_msg);
    auto final_msg = messages_1to2[1];
    const auto* payload_data = final_msg.payload.data();
    auto payload_size = final_msg.payload.size();

    REQUIRE(channels2.recv_authenticated(
      nid1,
      {final_msg.authenticated_hdr.data(), final_msg.authenticated_hdr.size()},
      payload_data,
      payload_size));
  }
}

TEST_CASE("Host connections")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel_kp = crypto::make_key_pair(default_curve);
  auto channel_cert =
    generate_endorsed_cert(channel_kp, "CN=Node", network_kp, service_cert);

  auto channel_manager = NodeToNodeChannelManager(wf1);
  channel_manager.initialize(nid1, service_cert, channel_kp, channel_cert);

  INFO("New node association is sent as ringbuffer message");
  {
    channel_manager.associate_node_address(nid2, "hostname", "port");
    auto add_node_msgs = read_node_msgs(eio1);
    REQUIRE(add_node_msgs.size() == 1);
    REQUIRE(std::get<0>(add_node_msgs[0]) == nid2);
    REQUIRE(std::get<1>(add_node_msgs[0]) == "hostname");
    REQUIRE(std::get<2>(add_node_msgs[0]) == "port");
  }

  INFO(
    "Trying to talk to node will initiate key exchange, regardless of IP "
    "association");
  {
    NodeId unknown_peer_id = std::string("unknown_peer");
    MsgType msg;
    msg.fill(0x42);
    channel_manager.send_authenticated(
      unknown_peer_id, NodeMsgType::consensus_msg, msg.data(), msg.size());
    auto outbound = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound.size() == 1);
    REQUIRE(outbound[0].type == channel_msg);
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

TEST_CASE("Concurrent key exchange init")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node1", network_kp, service_cert);

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);
  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);

  MsgType msg;
  msg.fill(0x42);

  {
    INFO("Channel 2 wins");
    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());
    channels2.send_authenticated(
      nid1, NodeMsgType::consensus_msg, msg.data(), msg.size());

    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == INITIATED);

    auto fst1 = get_first(eio1, NodeMsgType::channel_msg);
    auto fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, fst2.data()));
    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));

    REQUIRE(channels1.get_status(nid2) == WAITING_FOR_FINAL);
    REQUIRE(channels2.get_status(nid1) == INITIATED);

    fst1 = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));

    fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, fst2.data()));

    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);
  }

  channels1.close_channel(nid2);
  channels2.close_channel(nid1);

  read_outbound_msgs<MsgType>(eio1);
  read_outbound_msgs<MsgType>(eio2);

  {
    INFO("Channel 1 wins");
    // Node 2 is higher priority, so its init attempt will win if they happen
    // concurrently. However if node 1's init is received first, node 2 will use
    // it.

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());

    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == INACTIVE);

    // Node 2 receives the init _before_ any excuse to init themselves
    auto fst1 = get_first(eio1, NodeMsgType::channel_msg);
    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));
    channels2.send_authenticated(
      nid1, NodeMsgType::consensus_msg, msg.data(), msg.size());

    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);

    auto fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, fst2.data()));

    fst1 = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));

    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);
  }

  get_all_msgs({&eio1, &eio2});
}

struct CurveChoices
{
  crypto::CurveID network;
  crypto::CurveID node_1;
  crypto::CurveID node_2;
};

TEST_CASE("Full NodeToNode test")
{
  constexpr auto all_256 = CurveChoices{
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1};
  constexpr auto all_384 = CurveChoices{
    crypto::CurveID::SECP384R1,
    crypto::CurveID::SECP384R1,
    crypto::CurveID::SECP384R1};
  // One node on a different curve
  constexpr auto mixed_0 = CurveChoices{
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP384R1};
  // Both nodes on a different curve
  constexpr auto mixed_1 = CurveChoices{
    crypto::CurveID::SECP384R1,
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1};

  size_t i = 0;
  for (const auto& curves : {all_256, all_384, mixed_0, mixed_1})
  {
    LOG_DEBUG_FMT("Iteration: {}", i++);

    auto network_kp = crypto::make_key_pair(curves.network);
    auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

    auto ni1 = std::string("N1");
    auto channel1_kp = crypto::make_key_pair(curves.node_1);
    auto channel1_cert =
      generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

    auto ni2 = std::string("N2");
    auto channel2_kp = crypto::make_key_pair(curves.node_2);
    auto channel2_cert =
      generate_endorsed_cert(channel2_kp, "CN=Node2", network_kp, service_cert);

    size_t message_limit = 32;

    MsgType msg;
    msg.fill(0x42);

    INFO("Set up channels");
    NodeToNodeChannelManager n2n1(wf1), n2n2(wf2);

    n2n1.initialize(ni1, service_cert, channel1_kp, channel1_cert);
    n2n1.set_message_limit(message_limit);
    n2n2.initialize(ni2, service_cert, channel2_kp, channel2_cert);
    n2n2.set_message_limit(message_limit);

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
                n2n.recv_channel_message(msg.from, msg.data());

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

TEST_CASE("Interrupted key exchange")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node1", network_kp, service_cert);

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);
  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);

  std::vector<uint8_t> msg;
  msg.push_back(0x1);
  msg.push_back(0x0);
  msg.push_back(0x10);
  msg.push_back(0x42);

  enum class DropStage
  {
    InitiationMessage,
    ResponseMessage,
    FinalMessage,
    NoDrops,
  };

  DropStage drop_stage;
  for (const auto drop_stage : {
         DropStage::NoDrops,
         DropStage::FinalMessage,
         DropStage::ResponseMessage,
         DropStage::InitiationMessage,
       })
  {
    INFO("Drop stage is ", (size_t)drop_stage);

    auto n = read_outbound_msgs<MsgType>(eio1).size() +
      read_outbound_msgs<MsgType>(eio2).size();
    REQUIRE(n == 0);

    channels1.close_channel(nid2);
    channels2.close_channel(nid1);
    REQUIRE(channels1.get_status(nid2) == INACTIVE);
    REQUIRE(channels2.get_status(nid1) == INACTIVE);

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());

    REQUIRE(channels1.get_status(nid2) == INITIATED);
    REQUIRE(channels2.get_status(nid1) == INACTIVE);

    auto initiator_key_share_msg = get_first(eio1, NodeMsgType::channel_msg);
    if (drop_stage > DropStage::InitiationMessage)
    {
      REQUIRE(
        channels2.recv_channel_message(nid1, initiator_key_share_msg.data()));

      REQUIRE(channels1.get_status(nid2) == INITIATED);
      REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);

      auto responder_key_share_msg = get_first(eio2, NodeMsgType::channel_msg);
      if (drop_stage > DropStage::ResponseMessage)
      {
        REQUIRE(
          channels1.recv_channel_message(nid2, responder_key_share_msg.data()));

        REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
        REQUIRE(channels2.get_status(nid1) == WAITING_FOR_FINAL);

        auto initiator_key_exchange_final_msg =
          get_first(eio1, NodeMsgType::channel_msg);
        if (drop_stage > DropStage::FinalMessage)
        {
          REQUIRE(channels2.recv_channel_message(
            nid1, initiator_key_exchange_final_msg.data()));

          REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
          REQUIRE(channels2.get_status(nid1) == ESTABLISHED);
        }
      }
    }

    INFO("Later attempts to connect should succeed");
    {
      // Discard any pending messages
      channels1.close_channel(nid2);
      channels2.close_channel(nid1);

      SUBCASE("")
      {
        INFO("Node 1 attempts to connect");
        channels1.send_authenticated(
          nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());

        REQUIRE(channels2.recv_channel_message(
          nid1, get_first(eio1, NodeMsgType::channel_msg).data()));
        REQUIRE(channels1.recv_channel_message(
          nid2, get_first(eio2, NodeMsgType::channel_msg).data()));
        REQUIRE(channels2.recv_channel_message(
          nid1, get_first(eio1, NodeMsgType::channel_msg).data()));
      }
      else
      {
        INFO("Node 2 attempts to connect");
        channels2.send_authenticated(
          nid1, NodeMsgType::consensus_msg, msg.data(), msg.size());

        REQUIRE(channels1.recv_channel_message(
          nid2, get_first(eio2, NodeMsgType::channel_msg).data()));
        REQUIRE(channels2.recv_channel_message(
          nid1, get_first(eio1, NodeMsgType::channel_msg).data()));
        REQUIRE(channels1.recv_channel_message(
          nid2, get_first(eio2, NodeMsgType::channel_msg).data()));
      }
      REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
      REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

      MsgType aad;
      aad.fill(0x10);

      REQUIRE(channels1.send_encrypted(
        nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, msg));
      auto msg1 = get_first(eio1, NodeMsgType::consensus_msg);
      auto decrypted1 = channels2.recv_encrypted(
        nid1,
        {msg1.authenticated_hdr.data(), msg1.authenticated_hdr.size()},
        msg1.payload.data(),
        msg1.payload.size());
      REQUIRE(decrypted1 == msg);

      REQUIRE(channels2.send_encrypted(
        nid1, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, msg));
      auto msg2 = get_first(eio2, NodeMsgType::consensus_msg);
      auto decrypted2 = channels1.recv_encrypted(
        nid2,
        {msg2.authenticated_hdr.data(), msg2.authenticated_hdr.size()},
        msg2.payload.data(),
        msg2.payload.size());
      REQUIRE(decrypted2 == msg);
    }
  }
}

TEST_CASE("Expired certs")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel2_kp = crypto::make_key_pair(default_curve);

  auto service_cert = generate_self_signed_cert(network_kp, "CN=MyNetwork");
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node2", network_kp, service_cert);

  SUBCASE("Expired service cert")
  {
    service_cert = generate_self_signed_cert(network_kp, "CN=MyNetwork", true);
  }
  SUBCASE("Expired sender cert")
  {
    channel1_cert = generate_endorsed_cert(
      channel1_kp,
      "CN=Node1",
      network_kp,
      service_cert,
      // Generate expired cert
      true);
  }
  SUBCASE("Expired receiver cert")
  {
    channel2_cert = generate_endorsed_cert(
      channel2_kp,
      "CN=Node2",
      network_kp,
      service_cert,
      // Generate expired cert
      true);
  }

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);

  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);

  std::vector<uint8_t> payload;
  payload.push_back(0x1);
  payload.push_back(0x0);
  payload.push_back(0x10);
  payload.push_back(0x42);

  channels1.send_authenticated(
    nid2, NodeMsgType::consensus_msg, payload.data(), payload.size());

  auto msgs = read_outbound_msgs<MsgType>(eio1);
  for (const auto& msg : msgs)
  {
    REQUIRE(channels2.recv_channel_message(nid1, msg.data()));
  }
}

TEST_CASE("Robust key exchange")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node1", network_kp, service_cert);

  const NodeId nid3 = std::string("nid3");

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);
  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);

  MsgType aad;
  aad.fill(0x10);

  std::vector<uint8_t> payload;
  payload.push_back(0x1);
  payload.push_back(0x0);
  payload.push_back(0x10);
  payload.push_back(0x42);

  std::vector<std::tuple<std::string, size_t, std::vector<uint8_t>>>
    old_messages;
  {
    INFO("Build a collection of old messages that could confuse the protocol");

    channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    channels1.send_encrypted(
      nid3, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);

    auto outbound = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound.size() >= 2);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(std::make_tuple("too-early junk", i, msg.data()));
    }

    channels1.close_channel(nid2);
    channels1.close_channel(nid3);
    channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    channels1.send_encrypted(
      nid3, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);

    outbound = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound.size() >= 1);
    auto kex_init = outbound.back();
    REQUIRE(kex_init.type == NodeMsgType::channel_msg);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(std::make_tuple("initiation junk", i, msg.data()));
    }

    channels2.send_encrypted(
      nid1, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    channels2.send_encrypted(
      nid1, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    channels2.send_encrypted(
      nid3, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);

    outbound = read_outbound_msgs<MsgType>(eio2);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(
        std::make_tuple("counter-initiation junk", i, msg.data()));
    }

    // Close attempted init, so we accept (lower priority) incoming init
    channels2.close_channel(nid1);

    REQUIRE(channels2.recv_channel_message(nid1, kex_init.data()));
    // Replaying an init is fine, equivalent to making a new attempt
    // NB: Node 2 is now working with the _second_ exchange attempt, so to
    // succeed we must deliver that instance
    REQUIRE(channels2.recv_channel_message(nid1, kex_init.data()));

    outbound = read_outbound_msgs<MsgType>(eio2);
    REQUIRE(outbound.size() >= 2);
    auto kex_response = outbound.back();
    REQUIRE(kex_response.type == NodeMsgType::channel_msg);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(std::make_tuple("response junk", i, msg.data()));
    }

    REQUIRE(channels1.recv_channel_message(nid2, kex_response.data()));
    REQUIRE_FALSE(channels1.recv_channel_message(nid2, kex_response.data()));

    outbound = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(outbound.size() == 2);
    auto kex_final = outbound[0];
    REQUIRE(kex_final.type == NodeMsgType::channel_msg);
    REQUIRE(outbound[1].type == NodeMsgType::consensus_msg);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(std::make_tuple("final junk", i, msg.data()));
    }

    REQUIRE(channels2.recv_channel_message(nid1, kex_final.data()));
    REQUIRE_FALSE(channels2.recv_channel_message(nid1, kex_final.data()));

    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

    REQUIRE(channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload));
    channels1.send_encrypted(
      nid3, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);
    REQUIRE(channels2.send_encrypted(
      nid1, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload));
    channels2.send_encrypted(
      nid3, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload);

    outbound = read_outbound_msgs<MsgType>(eio1);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(std::make_tuple("tailing junk A", i, msg.data()));
    }

    outbound = read_outbound_msgs<MsgType>(eio2);
    for (size_t i = 0; i < outbound.size(); ++i)
    {
      const auto& msg = outbound[i];
      old_messages.push_back(std::make_tuple("tailing junk B", i, msg.data()));
    }
  }

  channels1.close_channel(nid2);
  channels2.close_channel(nid1);

  {
    INFO("Mix key exchange with old messages");

    auto receive_junk = [&]() {
      std::random_device rd;
      std::mt19937 g(rd());
      std::shuffle(old_messages.begin(), old_messages.end(), g);

      for (const auto& [label, i, msg] : old_messages)
      {
        // Uncomment this line to aid debugging if any of these fail
        // std::cout << label << ": " << i << std::endl;
        auto msg_1 = msg;
        channels1.recv_channel_message(nid2, std::move(msg_1));
        auto msg_2 = msg;
        channels2.recv_channel_message(nid1, std::move(msg_2));

        // Remove anything they responded with from the ringbuffer
        read_outbound_msgs<MsgType>(eio1);
        read_outbound_msgs<MsgType>(eio2);
      }
    };

    receive_junk();

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, payload.data(), payload.size());

    receive_junk();

    channels1.close_channel(nid2);
    channels2.close_channel(nid1);

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, payload.data(), payload.size());
    auto kex_init = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channels2.recv_channel_message(nid1, kex_init.data()));

    receive_junk();

    channels1.close_channel(nid2);
    channels2.close_channel(nid1);

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, payload.data(), payload.size());
    kex_init = get_first(eio1, NodeMsgType::channel_msg);
    REQUIRE(channels2.recv_channel_message(nid1, kex_init.data()));
    auto kex_response = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, kex_response.data()));

    receive_junk();

    channels1.close_channel(nid2);
    channels2.close_channel(nid1);

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, payload.data(), payload.size());
    kex_init = get_first(eio1, NodeMsgType::channel_msg);
    REQUIRE(channels2.recv_channel_message(nid1, kex_init.data()));
    kex_response = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, kex_response.data()));
    auto kex_final = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channels2.recv_channel_message(nid1, kex_final.data()));

    REQUIRE(channels1.get_status(nid2) == ESTABLISHED);
    REQUIRE(channels2.get_status(nid1) == ESTABLISHED);

    // We are not robust to new inits here!
    // receive_junk();

    REQUIRE(channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload));
    REQUIRE(channels2.send_encrypted(
      nid1, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload));
  }
}

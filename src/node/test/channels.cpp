// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define OVERRIDE_DEFAULT_N2N_MESSAGE_LIMIT 1000

#include "../channels.h"

#include "ccf/crypto/verifier.h"
#include "ccf/ds/hex.h"
#include "crypto/certs.h"
#include "crypto/openssl/x509_time.h"
#include "ds/non_blocking.h"
#include "ds/ring_buffer.h"
#include "node/node_to_node_channel_manager.h"
#include "node/node_types.h"

#include <algorithm>
#include <cstring>
#include <queue>
#include <random>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

namespace ccf::enclavetime
{
  std::atomic<long long>* host_time_us = nullptr;
  std::atomic<std::chrono::microseconds> last_value(
    std::chrono::microseconds(0));
}

namespace ccf
{
  std::chrono::microseconds Channel::min_gap_between_initiation_attempts(0);
}

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

class IORingbuffersFixture
{
protected:
  static constexpr size_t buffer_size = 1024 * 8;

  std::unique_ptr<ringbuffer::TestBuffer> in_buffer_1 =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  std::unique_ptr<ringbuffer::TestBuffer> out_buffer_1 =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio1 =
    ringbuffer::Circuit(in_buffer_1->bd, out_buffer_1->bd);

  std::unique_ptr<ringbuffer::TestBuffer> in_buffer_2 =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  std::unique_ptr<ringbuffer::TestBuffer> out_buffer_2 =
    std::make_unique<ringbuffer::TestBuffer>(buffer_size);
  ringbuffer::Circuit eio2 =
    ringbuffer::Circuit(in_buffer_2->bd, out_buffer_2->bd);

  ringbuffer::WriterFactory wf1 = ringbuffer::WriterFactory(eio1);
  ringbuffer::WriterFactory wf2 = ringbuffer::WriterFactory(eio2);
};

using namespace ccf;

// Use fixed-size messages as channels messages are not length-prefixed since
// the type of the authenticated header is known in advance (e.g. AppendEntries)
static constexpr auto msg_size = 64;
using MsgType = std::array<uint8_t, msg_size>;

static const NodeId nid1 = std::string("nid1");
static const NodeId nid2 = std::string("nid2");

static constexpr auto default_curve = crypto::CurveID::SECP384R1;

static std::pair<std::string, size_t> make_validity_pair(bool expired)
{
  using namespace std::literals;
  const auto now = std::chrono::system_clock::now();
  constexpr size_t validity_days = 365;
  if (expired)
  {
    return std::make_pair(
      ::ds::to_x509_time_string(now - std::chrono::days(2 * validity_days)),
      validity_days);
  }
  else
  {
    return std::make_pair(::ds::to_x509_time_string(now - 24h), validity_days);
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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Client/Server key exchange")
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
    // Queue 2 messages on channel1
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));
    REQUIRE(channels1.send_authenticated(
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
    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));
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
    REQUIRE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));
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
    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));
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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Replay and out-of-order")
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
    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

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
    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());
    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

    REQUIRE(channels2.recv_channel_message(
      nid1, get_first(eio1, NodeMsgType::channel_msg).data()));
    REQUIRE_FALSE(channels1.channel_open(nid2));
    // Node 2 still believes channel is open, using previously agreed keys
    REQUIRE(channels2.channel_open(nid1));

    REQUIRE(channels1.recv_channel_message(
      nid2, get_first(eio2, NodeMsgType::channel_msg).data()));
    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

    auto messages_1to2 = read_outbound_msgs<MsgType>(eio1);
    REQUIRE(messages_1to2.size() == 2);
    REQUIRE(messages_1to2[0].type == NodeMsgType::channel_msg);
    REQUIRE(channels2.recv_channel_message(nid1, messages_1to2[0].data()));
    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Host connections")
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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Concurrent key exchange init")
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

    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));

    auto fst1 = get_first(eio1, NodeMsgType::channel_msg);
    auto fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, fst2.data()));
    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));

    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));

    fst1 = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));

    fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, fst2.data()));

    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));
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

    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));

    // Node 2 receives the init _before_ any excuse to init themselves
    auto fst1 = get_first(eio1, NodeMsgType::channel_msg);
    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));
    channels2.send_authenticated(
      nid1, NodeMsgType::consensus_msg, msg.data(), msg.size());

    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));

    auto fst2 = get_first(eio2, NodeMsgType::channel_msg);

    REQUIRE(channels1.recv_channel_message(nid2, fst2.data()));

    fst1 = get_first(eio1, NodeMsgType::channel_msg);

    REQUIRE(channels2.recv_channel_message(nid1, fst1.data()));

    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));
  }

  get_all_msgs({&eio1, &eio2});
}

struct CurveChoices
{
  crypto::CurveID network;
  crypto::CurveID node_1;
  crypto::CurveID node_2;
};

TEST_CASE_FIXTURE(IORingbuffersFixture, "Full NodeToNode test")
{
  constexpr auto all_256 = CurveChoices{
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1};
  constexpr auto all_384 = CurveChoices{
    crypto::CurveID::SECP384R1,
    crypto::CurveID::SECP384R1,
    crypto::CurveID::SECP384R1};
  // One backup on a different curve
  constexpr auto mixed_0 = CurveChoices{
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP256R1,
    crypto::CurveID::SECP384R1};
  // Both backups on a different curve
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

    const auto seed = time(NULL);
    INFO("Using seed: ", seed);
    srand(seed);

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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Interrupted key exchange")
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
    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));

    channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.data(), msg.size());

    REQUIRE_FALSE(channels1.channel_open(nid2));
    REQUIRE_FALSE(channels2.channel_open(nid1));

    auto initiator_key_share_msg = get_first(eio1, NodeMsgType::channel_msg);
    if (drop_stage > DropStage::InitiationMessage)
    {
      REQUIRE(
        channels2.recv_channel_message(nid1, initiator_key_share_msg.data()));

      REQUIRE_FALSE(channels1.channel_open(nid2));
      REQUIRE_FALSE(channels2.channel_open(nid1));

      auto responder_key_share_msg = get_first(eio2, NodeMsgType::channel_msg);
      if (drop_stage > DropStage::ResponseMessage)
      {
        REQUIRE(
          channels1.recv_channel_message(nid2, responder_key_share_msg.data()));

        REQUIRE(channels1.channel_open(nid2));
        REQUIRE_FALSE(channels2.channel_open(nid1));

        auto initiator_key_exchange_final_msg =
          get_first(eio1, NodeMsgType::channel_msg);
        if (drop_stage > DropStage::FinalMessage)
        {
          REQUIRE(channels2.recv_channel_message(
            nid1, initiator_key_exchange_final_msg.data()));

          REQUIRE(channels1.channel_open(nid2));
          REQUIRE(channels2.channel_open(nid1));
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
      REQUIRE(channels1.channel_open(nid2));
      REQUIRE(channels2.channel_open(nid1));

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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Stuttering handshake")
{
  MsgType aad;
  aad.fill(0x10);

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

  std::vector<uint8_t> msg_body;
  msg_body.push_back(0x1);
  msg_body.push_back(0x2);
  msg_body.push_back(0x10);
  msg_body.push_back(0x42);

  INFO("Send an initial request, starting a handshake");
  REQUIRE(channels1.send_encrypted(
    nid2, NodeMsgType::forwarded_msg, {aad.begin(), aad.size()}, msg_body));

  INFO("Send a second request, triggering a second handshake");
  REQUIRE(channels1.send_encrypted(
    nid2, NodeMsgType::forwarded_msg, {aad.begin(), aad.size()}, msg_body));

  INFO("Receive first init message");
  auto q = read_outbound_msgs<MsgType>(eio1);
  REQUIRE(q.size() == 2);

  const auto init1 = q[0];
  REQUIRE(init1.type == NodeMsgType::channel_msg);
  REQUIRE(channels2.recv_channel_message(init1.from, init1.data()));

  INFO("Receive response to first handshake");
  const auto resp1 = get_first(eio2, NodeMsgType::channel_msg);
  REQUIRE_FALSE(channels1.recv_channel_message(resp1.from, resp1.data()));

  INFO("Receive second init message");
  const auto init2 = q[1];
  REQUIRE(init2.type == NodeMsgType::channel_msg);
  REQUIRE(channels2.recv_channel_message(init2.from, init2.data()));

  INFO("Receive response to second handshake");
  const auto resp2 = get_first(eio2, NodeMsgType::channel_msg);
  REQUIRE(channels1.recv_channel_message(resp2.from, resp2.data()));

  INFO("Receive final");
  q = read_outbound_msgs<MsgType>(eio1);
  REQUIRE(q.size() == 3);

  const auto fin = q[0];
  REQUIRE(fin.type == NodeMsgType::channel_msg);
  REQUIRE(channels2.recv_channel_message(fin.from, fin.data()));

  INFO("Decrypt original message");
  const auto received = q[1];
  REQUIRE(received.type == NodeMsgType::forwarded_msg);
  const auto decrypted = channels2.recv_encrypted(
    received.from,
    {received.authenticated_hdr.data(), received.authenticated_hdr.size()},
    received.payload.data(),
    received.payload.size());

  REQUIRE(decrypted == msg_body);
}

TEST_CASE_FIXTURE(IORingbuffersFixture, "Expired certs")
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

TEST_CASE_FIXTURE(IORingbuffersFixture, "Robust key exchange")
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

    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

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

    REQUIRE(channels1.channel_open(nid2));
    REQUIRE(channels2.channel_open(nid1));

    // We are not robust to new inits here!
    // receive_junk();

    REQUIRE(channels1.send_encrypted(
      nid2, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload));
    REQUIRE(channels2.send_encrypted(
      nid1, NodeMsgType::consensus_msg, {aad.data(), aad.size()}, payload));
  }
}

// Run separate threads simulating each node, sending many messages in both
// direction. Goal is that the message stream is uninterrupted, despite multiple
// key rotation exchanges happening during the sequence
TEST_CASE_FIXTURE(IORingbuffersFixture, "Key rotation")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  MsgType aad;
  aad.fill(0x42);

  struct QueueWithLock
  {
    std::mutex lock;
    std::vector<std::pair<ccf::NodeId, std::vector<uint8_t>>> to_send;
  };

  using ReceivedMessages = std::vector<std::vector<uint8_t>>;

  static constexpr auto message_limit = 40;

  std::atomic<bool> finished = false;
  auto run_channel = [&](
                       ccf::NodeId my_node_id,
                       ringbuffer::Circuit& source_buffer,
                       ringbuffer::AbstractWriterFactory& writer_factory,
                       QueueWithLock& send_queue,
                       ReceivedMessages& received_results) {
    auto kp = crypto::make_key_pair(default_curve);
    auto cert = generate_endorsed_cert(
      kp, fmt::format("CN={}", my_node_id), network_kp, service_cert);

    auto channels = NodeToNodeChannelManager(writer_factory);
    channels.initialize(my_node_id, service_cert, kp, cert);
    channels.set_message_limit(message_limit);

    while (!finished)
    {
      {
        // Send any new messages added to your work queue
        std::lock_guard<std::mutex> guard(send_queue.lock);
        for (auto& queued_msg : send_queue.to_send)
        {
          auto peer_id = queued_msg.first;
          auto& msg_body = queued_msg.second;
          REQUIRE(channels.send_encrypted(
            peer_id,
            NodeMsgType::forwarded_msg,
            {aad.begin(), aad.size()},
            msg_body));
        }
        send_queue.to_send.clear();
      }

      // Read and process all messages from peer
      auto msgs = read_outbound_msgs<MsgType>(source_buffer);
      for (auto& msg : msgs)
      {
        REQUIRE(msg.to == my_node_id);
        switch (msg.type)
        {
          case channel_msg:
          {
            channels.recv_channel_message(msg.from, msg.data());
            break;
          }

          case forwarded_msg:
          {
            auto decrypted = channels.recv_encrypted(
              msg.from,
              {msg.authenticated_hdr.data(), msg.authenticated_hdr.size()},
              msg.payload.data(),
              msg.payload.size());
            received_results.emplace_back(decrypted);
            break;
          }

          default:
          {
            throw std::runtime_error("Unexpected message type");
          }
        }
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  };

  QueueWithLock sent_by_1;
  ringbuffer::NonBlockingWriterFactory nbwf1(wf1);
  ReceivedMessages received_by_1;
  ReceivedMessages expected_received_by_1;
  std::thread channels1(
    run_channel,
    std::ref(nid1),
    std::ref(eio2),
    std::ref(nbwf1),
    std::ref(sent_by_1),
    std::ref(received_by_1));

  QueueWithLock sent_by_2;
  ringbuffer::NonBlockingWriterFactory nbwf2(wf2);
  ReceivedMessages received_by_2;
  ReceivedMessages expected_received_by_2;
  std::thread channels2(
    run_channel,
    std::ref(nid2),
    std::ref(eio1),
    std::ref(nbwf2),
    std::ref(sent_by_2),
    std::ref(received_by_2));

  // Submit a randomly generated workload
  for (auto i = 0; i < 5 * message_limit; ++i)
  {
    ccf::NodeId peer_nid;
    QueueWithLock* send_queue;
    ReceivedMessages* expected_results;
    if (rand() % 2 == 0)
    {
      peer_nid = nid2;
      send_queue = &sent_by_1;
      expected_results = &expected_received_by_2;
    }
    else
    {
      peer_nid = nid1;
      send_queue = &sent_by_2;
      expected_results = &expected_received_by_1;
    }

    {
      std::lock_guard<std::mutex> guard(send_queue->lock);
      std::vector<uint8_t> msg_body(rand() % 20);
      for (auto& n : msg_body)
      {
        n = rand();
      }
      send_queue->to_send.emplace_back(std::make_pair(peer_nid, msg_body));
      expected_results->emplace_back(msg_body);
    }

    // If we do not sleep here, we submit many messages at once, resulting in a
    // node's pending send queue filling up and a failure result when it calls
    // `send_encrypted`. A real application should handle this error code, and
    // set parameters so it is extremely rare. Here we simply sleep so that the
    // sends happen one-at-a-time.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  // Wait for channel threads to fully catch up.
  constexpr int wait_finish_attempts = 100;
  for (int attempt = 0; attempt < wait_finish_attempts; attempt++)
  {
    bool skip_waiting{true};
    {
      std::lock_guard<std::mutex> guard(sent_by_1.lock);
      skip_waiting &= sent_by_1.to_send.empty();
    }
    {
      std::lock_guard<std::mutex> guard(sent_by_2.lock);
      skip_waiting &= sent_by_2.to_send.empty();
    }
    if (skip_waiting)
    {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  finished.store(true);

  channels1.join();
  channels2.join();

  {
    std::lock_guard<std::mutex> guard(sent_by_1.lock);
    REQUIRE(sent_by_1.to_send.empty());
  }
  {
    std::lock_guard<std::mutex> guard(sent_by_2.lock);
    REQUIRE(sent_by_2.to_send.empty());
  }

  // Validate results
  REQUIRE(received_by_1 == expected_received_by_1);
  REQUIRE(received_by_2 == expected_received_by_2);
}

TEST_CASE_FIXTURE(IORingbuffersFixture, "Timeout idle channels")
{
  auto network_kp = crypto::make_key_pair(default_curve);
  auto service_cert = generate_self_signed_cert(network_kp, "CN=Network");

  auto channel1_kp = crypto::make_key_pair(default_curve);
  auto channel1_cert =
    generate_endorsed_cert(channel1_kp, "CN=Node1", network_kp, service_cert);

  auto channel2_kp = crypto::make_key_pair(default_curve);
  auto channel2_cert =
    generate_endorsed_cert(channel2_kp, "CN=Node2", network_kp, service_cert);

  const auto idle_timeout = std::chrono::milliseconds(10);
  const auto not_quite_idle = 2 * idle_timeout / 3;

  auto channels1 = NodeToNodeChannelManager(wf1);
  channels1.initialize(nid1, service_cert, channel1_kp, channel1_cert);
  channels1.set_idle_timeout(idle_timeout);

  auto channels2 = NodeToNodeChannelManager(wf2);
  channels2.initialize(nid2, service_cert, channel2_kp, channel2_cert);
  channels2.set_idle_timeout(idle_timeout);

  MsgType msg;
  msg.fill(0x42);

  {
    INFO("Idle channels are destroyed");
    REQUIRE_FALSE(channels1.have_channel(nid2));
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));

    REQUIRE_FALSE(channels2.have_channel(nid1));
    REQUIRE(channels2.send_authenticated(
      nid1, NodeMsgType::consensus_msg, msg.begin(), msg.size()));

    REQUIRE(channels1.have_channel(nid2));
    REQUIRE(channels2.have_channel(nid1));

    channels1.tick(not_quite_idle);
    REQUIRE(channels1.have_channel(nid2));
    REQUIRE(channels2.have_channel(nid1));

    channels1.tick(not_quite_idle);
    REQUIRE_FALSE(channels1.have_channel(nid2));
    REQUIRE(channels2.have_channel(nid1));

    channels2.tick(idle_timeout);
    REQUIRE_FALSE(channels1.have_channel(nid2));
    REQUIRE_FALSE(channels2.have_channel(nid1));

    // Flush previous messages
    read_outbound_msgs<MsgType>(eio1);
    read_outbound_msgs<MsgType>(eio2);
  }

  // Send some messages from 1 to 2. Confirm that those keep the channel (on
  // both ends) from being destroyed
  bool handshake_complete = false;

  for (size_t i = 0; i < 20; ++i)
  {
    REQUIRE(channels1.send_authenticated(
      nid2, NodeMsgType::consensus_msg, msg.begin(), msg.size()));

    auto msgs = read_outbound_msgs<MsgType>(eio1);
    for (const auto& msg : msgs)
    {
      switch (msg.type)
      {
        case NodeMsgType::channel_msg:
        {
          channels2.recv_channel_message(msg.from, msg.data());
          break;
        }
        case NodeMsgType::consensus_msg:
        {
          auto hdr = msg.authenticated_hdr;
          const auto* data = msg.payload.data();
          auto size = msg.payload.size();

          REQUIRE(channels2.recv_authenticated(
            msg.from, {hdr.data(), hdr.size()}, data, size));
          break;
        }
        default:
        {
          REQUIRE(false);
        }
      }
    }

    if (!handshake_complete)
    {
      // Deliver any responses from 2 to 1, to complete handshake
      msgs = read_outbound_msgs<MsgType>(eio2);
      if (msgs.empty())
      {
        handshake_complete = true;
      }
      else
      {
        for (const auto& msg : msgs)
        {
          switch (msg.type)
          {
            case NodeMsgType::channel_msg:
            {
              channels1.recv_channel_message(msg.from, msg.data());
              break;
            }
            default:
            {
              REQUIRE(false);
            }
          }
        }
      }
    }

    {
      INFO("Sends preserve channels");
      REQUIRE(channels1.have_channel(nid2));
    }

    {
      INFO("Receives preserve channels");
      REQUIRE(channels2.have_channel(nid1));
    }

    channels1.tick(not_quite_idle);
    channels2.tick(not_quite_idle);
  }

  REQUIRE(handshake_complete);

  {
    INFO("After comms, channels may still close due to idleness");
    channels1.tick(not_quite_idle);
    REQUIRE_FALSE(channels1.have_channel(nid2));

    channels2.tick(not_quite_idle);
    REQUIRE_FALSE(channels2.have_channel(nid1));
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../node_inbound_message.h"

#include "ccf/ds/nonstd.h"

#include <doctest/doctest.h>
#include <optional>
#include <vector>

namespace
{
  // Records the most recent message passed to it, so a test can assert whether
  // (and with what arguments) a particular handler was invoked.
  struct StubHandler
  {
    std::optional<ccf::NodeId> last_from;
    std::vector<uint8_t> last_payload;
    size_t call_count = 0;

    void recv_message(const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      last_from = from;
      last_payload.assign(data, data + size);
      ++call_count;
    }

    void recv_channel_message(
      const ccf::NodeId& from, const uint8_t* data, size_t size)
    {
      recv_message(from, data, size);
    }
  };

  std::vector<uint8_t> serialise_node_inbound(
    ccf::NodeMsgType msg_type,
    const ccf::NodeId& from,
    const std::vector<uint8_t>& payload)
  {
    auto sections =
      ringbuffer::MessageSerializers<ccf::node_inbound>::serialize(
        msg_type,
        from.value(),
        serializer::ByteRange{payload.data(), payload.size()});

    std::vector<uint8_t> result;
    ccf::nonstd::tuple_for_each(sections, [&](const auto& s) {
      result.insert(result.end(), s->data(), s->data() + s->size());
    });
    return result;
  }
}

TEST_CASE(
  "recv_node_inbound_message gating" *
  doctest::test_suite("node_inbound_message"))
{
  const ccf::NodeId from("0123456789abcdef");
  const std::vector<uint8_t> payload{1, 2, 3, 4, 5};

  const auto early_states = {
    ccf::NodeStartupState::uninitialized,
    ccf::NodeStartupState::initialized,
    ccf::NodeStartupState::pending,
    ccf::NodeStartupState::readingPublicLedger};

  const auto active_states = {
    ccf::NodeStartupState::partOfNetwork,
    ccf::NodeStartupState::partOfPublicNetwork,
    ccf::NodeStartupState::readingPrivateLedger};

  SUBCASE("Forwarded commands are not processed before part of network")
  {
    const auto serialised =
      serialise_node_inbound(ccf::forwarded_msg, from, payload);

    for (const auto state : early_states)
    {
      INFO("Early state: ", state);
      ds::StateMachine<ccf::NodeStartupState> sm("test", state);
      StubHandler forwarder;
      StubHandler channels;
      StubHandler consensus;

      ccf::recv_node_inbound_message(
        serialised.data(),
        serialised.size(),
        sm,
        forwarder,
        channels,
        consensus);

      REQUIRE(forwarder.call_count == 0);
      REQUIRE(channels.call_count == 0);
      REQUIRE(consensus.call_count == 0);
    }
  }

  SUBCASE("Forwarded commands are processed once part of network")
  {
    const auto serialised =
      serialise_node_inbound(ccf::forwarded_msg, from, payload);

    for (const auto state : active_states)
    {
      INFO("Active state: ", state);
      ds::StateMachine<ccf::NodeStartupState> sm("test", state);
      StubHandler forwarder;
      StubHandler channels;
      StubHandler consensus;

      ccf::recv_node_inbound_message(
        serialised.data(),
        serialised.size(),
        sm,
        forwarder,
        channels,
        consensus);

      REQUIRE(forwarder.call_count == 1);
      REQUIRE(forwarder.last_from == from);
      REQUIRE(forwarder.last_payload == payload);
      REQUIRE(channels.call_count == 0);
      REQUIRE(consensus.call_count == 0);
    }
  }

  SUBCASE("Channel messages are gated and dispatched identically")
  {
    const auto serialised =
      serialise_node_inbound(ccf::channel_msg, from, payload);

    {
      INFO("Dropped before part of network");
      ds::StateMachine<ccf::NodeStartupState> sm(
        "test", ccf::NodeStartupState::pending);
      StubHandler forwarder;
      StubHandler channels;
      StubHandler consensus;

      ccf::recv_node_inbound_message(
        serialised.data(),
        serialised.size(),
        sm,
        forwarder,
        channels,
        consensus);

      REQUIRE(channels.call_count == 0);
    }

    {
      INFO("Dispatched once part of network");
      ds::StateMachine<ccf::NodeStartupState> sm(
        "test", ccf::NodeStartupState::partOfNetwork);
      StubHandler forwarder;
      StubHandler channels;
      StubHandler consensus;

      ccf::recv_node_inbound_message(
        serialised.data(),
        serialised.size(),
        sm,
        forwarder,
        channels,
        consensus);

      REQUIRE(channels.call_count == 1);
      REQUIRE(channels.last_from == from);
      REQUIRE(channels.last_payload == payload);
      REQUIRE(forwarder.call_count == 0);
      REQUIRE(consensus.call_count == 0);
    }
  }

  SUBCASE("Consensus messages are gated and dispatched identically")
  {
    const auto serialised =
      serialise_node_inbound(ccf::consensus_msg, from, payload);

    {
      INFO("Dropped before part of network");
      ds::StateMachine<ccf::NodeStartupState> sm(
        "test", ccf::NodeStartupState::initialized);
      StubHandler forwarder;
      StubHandler channels;
      StubHandler consensus;

      ccf::recv_node_inbound_message(
        serialised.data(),
        serialised.size(),
        sm,
        forwarder,
        channels,
        consensus);

      REQUIRE(consensus.call_count == 0);
    }

    {
      INFO("Dispatched once part of network");
      ds::StateMachine<ccf::NodeStartupState> sm(
        "test", ccf::NodeStartupState::readingPrivateLedger);
      StubHandler forwarder;
      StubHandler channels;
      StubHandler consensus;

      ccf::recv_node_inbound_message(
        serialised.data(),
        serialised.size(),
        sm,
        forwarder,
        channels,
        consensus);

      REQUIRE(consensus.call_count == 1);
      REQUIRE(consensus.last_from == from);
      REQUIRE(consensus.last_payload == payload);
      REQUIRE(forwarder.call_count == 0);
      REQUIRE(channels.call_count == 0);
    }
  }
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../channels.h"

#include <doctest/doctest.h>

using namespace ccf;

TEST_CASE("Client/Server key exchange")
{
  Channel channel1, channel2;
  SeqNo iv_seq1 = 0;

  INFO("Trying to tag/verify before channel establishment");
  {
    std::vector<uint8_t> msg(128, 0x42);
    ccf::GcmHdr hdr;

    REQUIRE_THROWS_AS(channel1.tag(hdr, msg), std::logic_error);
    REQUIRE_THROWS_AS(channel2.verify(hdr, msg), std::logic_error);
  }

  INFO("Compute shared secret");
  {
    auto channel1_public = channel1.get_public();
    auto channel2_public = channel2.get_public();
    REQUIRE(channel1_public.has_value());
    REQUIRE(channel2_public.has_value());

    channel1.load_peer_public(
      channel2_public.value().data(), channel2_public.value().size());
    channel2.load_peer_public(
      channel1_public.value().data(), channel1_public.value().size());

    channel1.establish();
    channel2.establish();
  }

  INFO("Protect integrity of message (peer1 -> peer2)");
  {
    std::vector<uint8_t> msg(128, 0x42);
    ccf::GcmHdr hdr;

    channel1.tag(hdr, msg);
    REQUIRE(*reinterpret_cast<const uint64_t*>(hdr.getIv().p) == iv_seq1++);
    REQUIRE(channel2.verify(hdr, msg));
  }

  INFO("Protect integrity of message (peer2 -> peer1)");
  {
    std::vector<uint8_t> msg(128, 0x42);
    ccf::GcmHdr hdr;

    channel2.tag(hdr, msg);
    REQUIRE(channel1.verify(hdr, msg));
  }

  INFO("Tamper with message");
  {
    std::vector<uint8_t> msg(128, 0x42);
    ccf::GcmHdr hdr;

    channel1.tag(hdr, msg);
    REQUIRE(*reinterpret_cast<const uint64_t*>(hdr.getIv().p) == iv_seq1++);
    msg[50] = 0xFF;
    REQUIRE_FALSE(channel2.verify(hdr, msg));
  }

  INFO("Tamper with header");
  {
    std::vector<uint8_t> msg(128, 0x42);
    ccf::GcmHdr hdr;

    channel1.tag(hdr, msg);
    REQUIRE(*reinterpret_cast<const uint64_t*>(hdr.getIv().p) == iv_seq1++);
    hdr.iv[4] = hdr.iv[4] + 1;
    REQUIRE_FALSE(channel2.verify(hdr, msg));
  }

  INFO("Encrypt message (peer1 -> peer2)");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);
    ccf::GcmHdr hdr;

    channel1.encrypt(hdr, {}, plain, cipher);
    REQUIRE(*reinterpret_cast<const uint64_t*>(hdr.getIv().p) == iv_seq1++);
    REQUIRE(channel2.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE(plain == decrypted);
  }

  INFO("Encrypt message (peer2 -> peer1)");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);
    ccf::GcmHdr hdr;

    channel2.encrypt(hdr, {}, plain, cipher);
    REQUIRE(channel1.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE(plain == decrypted);
  }
}

TEST_CASE("Channel manager")
{
  NodeId leader_id = 1;
  NodeId follower_id = 2;
  NodeId other_id = 3;

  auto kp = tls::make_key_pair(), kp_other = tls::make_key_pair();
  auto network_pkey = kp->private_key();
  auto other_pkey = kp_other->private_key();

  ChannelManager leader_n2n_channel_manager(network_pkey);
  ChannelManager follower_n2n_channel_manager(network_pkey);
  ChannelManager other_n2n_channel_manager(other_pkey);

  INFO("Compute shared secret");
  {
    // Retrieve own signed public
    auto signed_leader_to_follower =
      leader_n2n_channel_manager.get_signed_public(follower_id);
    REQUIRE(signed_leader_to_follower.value().size() > 0);
    auto signed_follower_to_leader =
      follower_n2n_channel_manager.get_signed_public(leader_id);
    REQUIRE(signed_follower_to_leader.value().size() > 0);

    // Load peer public and compute shared secret
    REQUIRE(follower_n2n_channel_manager.load_peer_signed_public(
      leader_id, signed_leader_to_follower.value()));
    REQUIRE(leader_n2n_channel_manager.load_peer_signed_public(
      follower_id, signed_follower_to_leader.value()));

    // Retrieving own signed public once channel is established should fail
    REQUIRE(
      !follower_n2n_channel_manager.get_signed_public(leader_id).has_value());
    REQUIRE(
      !leader_n2n_channel_manager.get_signed_public(follower_id).has_value());
  }

  INFO("Try to compute shared secret with node not in network");
  {
    auto signed_leader_to_other =
      leader_n2n_channel_manager.get_signed_public(other_id);

    REQUIRE_FALSE(other_n2n_channel_manager.load_peer_signed_public(
      leader_id, signed_leader_to_other.value()));

    auto signed_other_to_leader =
      other_n2n_channel_manager.get_signed_public(leader_id);

    REQUIRE_FALSE(leader_n2n_channel_manager.load_peer_signed_public(
      other_id, signed_other_to_leader.value()));
  }

  auto& leader_channel_with_follower =
    leader_n2n_channel_manager.get(follower_id);
  auto& follower_channel_with_leader =
    follower_n2n_channel_manager.get(leader_id);

  INFO("Protect integrity of message (leader -> follower)");
  {
    std::vector<uint8_t> msg(128, 0x42);
    GcmHdr hdr;
    leader_channel_with_follower.tag(hdr, msg);
    REQUIRE(follower_channel_with_leader.verify(hdr, msg));
  }

  INFO("Protect integrity of message (follower -> leader)");
  {
    std::vector<uint8_t> msg(128, 0x42);
    GcmHdr hdr;
    follower_channel_with_leader.tag(hdr, msg);
    REQUIRE(leader_channel_with_follower.verify(hdr, msg));
  }

  INFO("Encrypt message (leader -> follower)");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);
    ccf::GcmHdr hdr;

    leader_channel_with_follower.encrypt(hdr, {}, plain, cipher);
    REQUIRE(follower_channel_with_leader.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE(plain == decrypted);
  }

  INFO("Encrypt message (follower -> leader)");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);
    ccf::GcmHdr hdr;

    follower_channel_with_leader.encrypt(hdr, {}, plain, cipher);
    REQUIRE(leader_channel_with_follower.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE(plain == decrypted);
  }
}

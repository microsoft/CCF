// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN

#include "../channels.h"

#include <doctest/doctest.h>

enclave::ThreadMessaging enclave::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> enclave::ThreadMessaging::thread_count = 0;

using namespace ccf;

TEST_CASE("Client/Server key exchange")
{
  Channel channel1, channel2;
  SeqNo iv_seq1 = 1;

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
    RecvNonce u(*reinterpret_cast<const uint64_t*>(hdr.get_iv().p));
    REQUIRE(u.nonce == iv_seq1++);
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
    RecvNonce u(*reinterpret_cast<const uint64_t*>(hdr.get_iv().p));
    REQUIRE(u.nonce == iv_seq1++);
    msg[50] = 0xFF;
    REQUIRE_FALSE(channel2.verify(hdr, msg));
  }

  INFO("Tamper with header");
  {
    std::vector<uint8_t> msg(128, 0x42);
    ccf::GcmHdr hdr;

    channel1.tag(hdr, msg);
    RecvNonce u(*reinterpret_cast<const uint64_t*>(hdr.get_iv().p));
    REQUIRE(u.nonce == iv_seq1++);
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
    RecvNonce u(*reinterpret_cast<const uint64_t*>(hdr.get_iv().p));
    REQUIRE(u.nonce == iv_seq1++);
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

TEST_CASE("Replay and out-of-order")
{
  Channel channel1, channel2;

  INFO("Compute shared secret");
  {
    channel1.load_peer_public(
      channel2.get_public().value().data(),
      channel2.get_public().value().size());
    channel2.load_peer_public(
      channel1.get_public().value().data(),
      channel1.get_public().value().size());
    channel1.establish();
    channel2.establish();
  }

  std::vector<uint8_t> msg(128, 0x42);
  ccf::GcmHdr hdr;

  INFO("First message");
  {
    channel1.tag(hdr, msg);
    REQUIRE(channel2.verify(hdr, msg));
  }

  INFO("Replay message");
  {
    REQUIRE_FALSE(channel2.verify(hdr, msg));
  }

  INFO("Skip some messages and replay");
  {
    ccf::GcmHdr hdr2;
    channel1.tag(hdr2, msg);
    channel1.tag(hdr2, msg);
    channel1.tag(hdr2, msg);

    REQUIRE(channel2.verify(hdr2, msg));
    REQUIRE_FALSE(channel2.verify(hdr, msg));
  }

  INFO("Replay and skip encrypted messages");
  {
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);

    channel1.encrypt(hdr, {}, msg, cipher);
    REQUIRE(channel2.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE_FALSE(channel2.decrypt(hdr, {}, cipher, decrypted));

    channel1.encrypt(hdr, {}, msg, cipher);
    channel1.encrypt(hdr, {}, msg, cipher);

    REQUIRE(channel2.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE_FALSE(channel2.decrypt(hdr, {}, cipher, decrypted));
  }
}

TEST_CASE("Channel manager")
{
  NodeId primary_id = 1;
  NodeId backup_id = 2;
  NodeId other_id = 3;

  auto kp = tls::make_key_pair(), kp_other = tls::make_key_pair();
  auto network_pkey = kp->private_key_pem();
  auto other_pkey = kp_other->private_key_pem();

  ChannelManager primary_n2n_channel_manager(network_pkey);
  ChannelManager backup_n2n_channel_manager(network_pkey);
  ChannelManager other_n2n_channel_manager(other_pkey);

  INFO("Compute shared secret");
  {
    // Retrieve own signed public
    auto signed_primary_to_backup =
      primary_n2n_channel_manager.get_signed_public(backup_id);
    REQUIRE(signed_primary_to_backup.value().size() > 0);
    auto signed_backup_to_primary =
      backup_n2n_channel_manager.get_signed_public(primary_id);
    REQUIRE(signed_backup_to_primary.value().size() > 0);

    // Load peer public and compute shared secret
    REQUIRE(backup_n2n_channel_manager.load_peer_signed_public(
      primary_id, signed_primary_to_backup.value()));
    REQUIRE(primary_n2n_channel_manager.load_peer_signed_public(
      backup_id, signed_backup_to_primary.value()));

    // Retrieving own signed public once channel is established should fail
    REQUIRE(
      !backup_n2n_channel_manager.get_signed_public(primary_id).has_value());
    REQUIRE(
      !primary_n2n_channel_manager.get_signed_public(backup_id).has_value());
  }

  INFO("Try to compute shared secret with node not in network");
  {
    auto signed_primary_to_other =
      primary_n2n_channel_manager.get_signed_public(other_id);

    REQUIRE_FALSE(other_n2n_channel_manager.load_peer_signed_public(
      primary_id, signed_primary_to_other.value()));

    auto signed_other_to_primary =
      other_n2n_channel_manager.get_signed_public(primary_id);

    REQUIRE_FALSE(primary_n2n_channel_manager.load_peer_signed_public(
      other_id, signed_other_to_primary.value()));
  }

  auto& primary_channel_with_backup =
    primary_n2n_channel_manager.get(backup_id);
  auto& backup_channel_with_primary =
    backup_n2n_channel_manager.get(primary_id);

  INFO("Protect integrity of message (primary -> backup)");
  {
    std::vector<uint8_t> msg(128, 0x42);
    GcmHdr hdr;
    primary_channel_with_backup.tag(hdr, msg);
    REQUIRE(backup_channel_with_primary.verify(hdr, msg));
  }

  INFO("Protect integrity of message (backup -> primary)");
  {
    std::vector<uint8_t> msg(128, 0x42);
    GcmHdr hdr;
    backup_channel_with_primary.tag(hdr, msg);
    REQUIRE(primary_channel_with_backup.verify(hdr, msg));
  }

  INFO("Encrypt message (primary -> backup)");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);
    ccf::GcmHdr hdr;

    primary_channel_with_backup.encrypt(hdr, {}, plain, cipher);
    REQUIRE(backup_channel_with_primary.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE(plain == decrypted);
  }

  INFO("Encrypt message (backup -> primary)");
  {
    std::vector<uint8_t> plain(128, 0x42);
    std::vector<uint8_t> cipher(128);
    std::vector<uint8_t> decrypted(128);
    ccf::GcmHdr hdr;

    backup_channel_with_primary.encrypt(hdr, {}, plain, cipher);
    REQUIRE(primary_channel_with_backup.decrypt(hdr, {}, cipher, decrypted));
    REQUIRE(plain == decrypted);
  }
}

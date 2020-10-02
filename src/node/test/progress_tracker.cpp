// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/progress_tracker.h"

#include "kv/store.h"
#include "node/nodes.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>
#include <trompeloeil/include/trompeloeil.hpp>

class StoreMock : public ccf::ProgressTrackerStore
{
public:
  MAKE_MOCK1(write_backup_signatures, void(ccf::BackupSignatures&), override);
  MAKE_MOCK0(
    get_backup_signatures, std::optional<ccf::BackupSignatures>(), override);
  MAKE_MOCK1(write_nonces, void(aft::RevealedNonces&), override);
  MAKE_MOCK0(get_nonces, std::optional<aft::RevealedNonces>(), override);
  MAKE_MOCK4(
    verify_signature,
    bool(kv::NodeId, crypto::Sha256Hash&, uint32_t, uint8_t*),
    override);
};

void run_ordered_execution(uint32_t my_node_id)
{
  using trompeloeil::_;

  auto store = std::make_unique<StoreMock>();
  StoreMock& store_mock = *store.get();
  auto pt =
    std::make_unique<ccf::ProgressTracker>(std::move(store), my_node_id);

  kv::Consensus::View view = 0;
  kv::Consensus::SeqNo seqno = 0;
  uint32_t node_count = 4;
  uint32_t node_count_quorum =
    2; // Takes into account that counting starts at 0

  crypto::Sha256Hash root;
  std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN> sig;
  ccf::Nonce nonce;
  auto h = pt->hash_data(nonce);
  ccf::Nonce hashed_nonce;
  std::copy(h.begin(), h.end(), hashed_nonce.begin());

  REQUIRE_CALL(store_mock, verify_signature(_, _, _, _))
    .RETURN(true)
    .TIMES(AT_LEAST(2));
  REQUIRE_CALL(store_mock, write_backup_signatures(_)).TIMES(1);
  REQUIRE_CALL(store_mock, write_nonces(_)).TIMES(1);

  INFO("Adding signatures");
  {
    auto result =
      pt->record_primary({view, seqno}, 0, root, hashed_nonce, node_count);
    REQUIRE(result == kv::TxHistory::Result::OK);

    for (uint32_t i = 1; i < node_count; ++i)
    {
      if (i == my_node_id)
      {
        auto h = pt->get_my_hashed_nonce({view, seqno});
        std::copy(h.begin(), h.end(), hashed_nonce.begin());
      }
      else
      {
        std::copy(h.begin(), h.end(), hashed_nonce.begin());
      }

      auto result = pt->add_signature(
        {view, seqno},
        i,
        MBEDTLS_ECDSA_MAX_LEN,
        sig,
        hashed_nonce,
        node_count,
        true);
      REQUIRE(
        ((result == kv::TxHistory::Result::OK && i != node_count_quorum) ||
         (result == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK &&
          i == node_count_quorum)));
    }
  }

  INFO("Add signature acks");
  {
    for (uint32_t i = 0; i < node_count; ++i)
    {
      auto result = pt->add_signature_ack({view, seqno}, i, node_count);
      REQUIRE(
        ((result == kv::TxHistory::Result::OK && i != node_count_quorum) ||
         (result == kv::TxHistory::Result::SEND_REPLY_AND_NONCE &&
          i == node_count_quorum)));
    }
  }

  INFO("Add nonces here");
  {
    for (uint32_t i = 0; i < node_count; ++i)
    {
      if (my_node_id == i)
      {
        pt->add_nonce_reveal(
          {view, seqno}, pt->get_my_nonce({view, seqno}), i, node_count, true);
      }
      else
      {
        pt->add_nonce_reveal({view, seqno}, nonce, i, node_count, true);
      }
    }
  }
}

TEST_CASE("Ordered Execution")
{
  for (uint32_t i = 0; i < 4; ++i)
  {
    run_ordered_execution(i);
  }
}

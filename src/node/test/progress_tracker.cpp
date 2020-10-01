// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/progress_tracker.h"

#include "kv/store.h"
#include "node/nodes.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <string>

class Store : public ccf::ProgressTrackerStore
{
public:
  void write_backup_signatures(ccf::BackupSignatures& sig_value) override {}
  std::optional<ccf::BackupSignatures> get_backup_signatures() override
  {
    return std::optional<ccf::BackupSignatures>();
  }
  void write_nonces(aft::RevealedNonces& nonces) override {}
  std::optional<aft::RevealedNonces> get_nonces() override
  {
    return std::optional<aft::RevealedNonces>();
  }
  bool verify_signature(
    kv::NodeId node_id,
    crypto::Sha256Hash& root,
    uint32_t sig_size,
    uint8_t* sig) override
  {
    return true;
  }
};

TEST_CASE("Ordered Execution")
{
  auto store = std::make_unique<Store>();
  auto pt = std::make_unique<ccf::ProgressTracker>(std::move(store), 0);

  kv::Consensus::View view = 0;
  kv::Consensus::SeqNo seqno = 0;
  uint32_t node_count = 4;

  crypto::Sha256Hash root;
  std::array<uint8_t, MBEDTLS_ECDSA_MAX_LEN> sig;
  ccf::Nonce nonce;
  nonce.fill(1);
  auto h = pt->hash_data(nonce);
  ccf::Nonce hashed_nonce;
  std::copy(h.begin(), h.end(), hashed_nonce.begin());

  INFO("Adding signatures");
  {
    ccf::Nonce nonce_tmp;
    auto result = pt->record_primary({view, seqno}, 0, root, nonce_tmp, node_count);
    REQUIRE(result == kv::TxHistory::Result::OK);

    for (uint32_t i = 1; i < node_count; ++i)
    {
      auto result = pt->add_signature(
        {view, seqno}, i, MBEDTLS_ECDSA_MAX_LEN, sig, hashed_nonce, node_count, true);
      REQUIRE(
        ((result == kv::TxHistory::Result::OK && i != 2) ||
         (result == kv::TxHistory::Result::SEND_SIG_RECEIPT_ACK && i == 2)));
    }
  }

  INFO("Add signature acks");
  {
    for (uint32_t i = 0; i < node_count; ++i)
    {
      auto result = pt->add_signature_ack(
        {view, seqno}, i, node_count);
      REQUIRE(
        ((result == kv::TxHistory::Result::OK && i != 2) ||
         (result == kv::TxHistory::Result::SEND_REPLY_AND_NONCE && i == 2)));
    }
  }

  INFO("Add nonces here");
  {
    pt->add_nonce_reveal(
      {view, seqno}, pt->get_my_nonce({view, seqno}), 0, node_count, true);
    for (uint32_t i = 1; i < node_count; ++i)
    {
      pt->add_nonce_reveal({view, seqno}, nonce, i, node_count, true);
    }
  }
}

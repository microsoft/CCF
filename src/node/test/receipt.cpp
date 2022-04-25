// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/receipt.h"

#include "ccf/crypto/key_pair.h"
#include "ccf/service/tables/nodes.h"
#include "ds/x509_time_fmt.h"

#include <doctest/doctest.h>
#include <iostream>
#include <random>

std::random_device rand_device;
std::default_random_engine rand_engine(rand_device());

crypto::Sha256Hash rand_digest()
{
  std::uniform_int_distribution<uint8_t> dist;

  crypto::Sha256Hash ret;
  std::generate(
    ret.h.begin(), ret.h.end(), [&]() { return dist(rand_engine); });

  return ret;
}

void populate_receipt(ccf::ReceiptPtr receipt)
{
  using namespace std::literals;
  const auto valid_from =
    ds::to_x509_time_string(std::chrono::system_clock::now() - 1h);
  const auto valid_to =
    ds::to_x509_time_string(std::chrono::system_clock::now() + 1h);

  auto node_kp = crypto::make_key_pair();
  auto node_cert = node_kp->self_sign("CN=node", valid_from, valid_to);

  receipt->cert = node_cert;
  receipt->node_id = ccf::compute_node_id_from_kp(node_kp);

  auto current_digest = receipt->get_leaf_digest();

  const auto num_proof_steps = rand() % 8;
  for (auto i = 0; i < num_proof_steps; ++i)
  {
    const auto dir = rand() % 2 == 0 ? ccf::Receipt::ProofStep::Left :
                                       ccf::Receipt::ProofStep::Right;
    const auto digest = rand_digest();

    ccf::Receipt::ProofStep step{dir, digest};
    receipt->proof.push_back(step);

    if (dir == ccf::Receipt::ProofStep::Left)
    {
      current_digest = crypto::Sha256Hash(digest, current_digest);
    }
    else
    {
      current_digest = crypto::Sha256Hash(current_digest, digest);
    }
  }

  const auto root = receipt->get_root();
  receipt->signature = node_kp->sign_hash(root.h.data(), root.h.size());

  const auto num_endorsements = (rand() % 3) + 2;
  for (auto i = 0; i < num_endorsements; ++i)
  {
    auto service_kp = crypto::make_key_pair();
    auto service_cert =
      service_kp->self_sign("CN=service", valid_from, valid_to);
    const auto csr = node_kp->create_csr(fmt::format("Test {}", i));
    const auto endorsement =
      service_kp->sign_csr(service_cert, csr, valid_from, valid_to);
    receipt->service_endorsements.push_back(endorsement);
  }
}

void compare_receipts(ccf::ReceiptPtr l, ccf::ReceiptPtr r)
{
  REQUIRE(l != nullptr);
  REQUIRE(r != nullptr);

  REQUIRE(l->signature == r->signature);
  REQUIRE(l->proof == r->proof);
  REQUIRE(l->node_id == r->node_id);
  REQUIRE(l->cert == r->cert);
  REQUIRE(l->service_endorsements == r->service_endorsements);

  if (auto ld_l = std::dynamic_pointer_cast<ccf::LeafDigestReceipt>(l))
  {
    auto ld_r = std::dynamic_pointer_cast<ccf::LeafDigestReceipt>(r);
    REQUIRE(ld_r != nullptr);

    REQUIRE(ld_l->leaf == ld_r->leaf);
  }
  else if (auto le_l = std::dynamic_pointer_cast<ccf::LeafExpandedReceipt>(l))
  {
    auto le_r = std::dynamic_pointer_cast<ccf::LeafExpandedReceipt>(r);
    REQUIRE(le_r != nullptr);

    REQUIRE(
      le_l->leaf_components.write_set_digest ==
      le_r->leaf_components.write_set_digest);
    REQUIRE(
      le_l->leaf_components.commit_evidence ==
      le_r->leaf_components.commit_evidence);
    REQUIRE(
      le_l->leaf_components.claims_digest ==
      le_r->leaf_components.claims_digest);
  }
}

TEST_CASE("JSON conversion")
{
  {
    std::shared_ptr<ccf::Receipt> r = nullptr;
    nlohmann::json j;
    REQUIRE_THROWS(to_json(j, r));
    REQUIRE_THROWS(from_json(j, r));
  }

  {
    INFO("LeafDigestReceipt");

    for (auto i = 0; i < 20; ++i)
    {
      auto ld_receipt = std::make_shared<ccf::LeafDigestReceipt>();
      ld_receipt->leaf = rand_digest();

      populate_receipt(ld_receipt);

      nlohmann::json j = ld_receipt;

      const auto parsed = j.get<ccf::ReceiptPtr>();
      compare_receipts(ld_receipt, parsed);
    }
  }
}
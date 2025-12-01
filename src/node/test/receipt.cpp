// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/receipt.h"

#include "ccf/crypto/ec_key_pair.h"
#include "ccf/ds/x509_time_fmt.h"
#include "ccf/service/tables/nodes.h"
#include "crypto/openssl/ec_key_pair.h"
#include "crypto/openssl/hash.h"

#include <doctest/doctest.h>
#include <iostream>
#include <random>

std::random_device rand_device;
std::default_random_engine rand_engine(rand_device());

ccf::crypto::Sha256Hash rand_digest()
{
  std::uniform_int_distribution<uint8_t> dist;

  ccf::crypto::Sha256Hash ret;
  std::generate(
    ret.h.begin(), ret.h.end(), [&]() { return dist(rand_engine); });

  return ret;
}

void populate_receipt(std::shared_ptr<ccf::ProofReceipt> receipt)
{
  using namespace std::literals;
  const auto valid_from =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() - 1h);
  const auto valid_to =
    ccf::ds::to_x509_time_string(std::chrono::system_clock::now() + 1h);

  auto node_kp = ccf::crypto::make_ec_key_pair();
  auto node_cert = node_kp->self_sign("CN=node", valid_from, valid_to);

  receipt->cert = node_cert;
  receipt->node_id = ccf::compute_node_id_from_kp(node_kp);

  auto current_digest = receipt->get_leaf_digest();

  const auto num_proof_steps = rand() % 8;
  for (auto i = 0; i < num_proof_steps; ++i)
  {
    const auto dir = rand() % 2 == 0 ?
      ccf::ProofReceipt::ProofStep::Direction::Left :
      ccf::ProofReceipt::ProofStep::Direction::Right;
    const auto digest = rand_digest();

    ccf::ProofReceipt::ProofStep step{dir, digest};
    receipt->proof.push_back(step);

    if (dir == ccf::ProofReceipt::ProofStep::Direction::Left)
    {
      current_digest = ccf::crypto::Sha256Hash(digest, current_digest);
    }
    else
    {
      current_digest = ccf::crypto::Sha256Hash(current_digest, digest);
    }
  }

  const auto root = receipt->calculate_root();
  REQUIRE(root == current_digest);
  receipt->signature = node_kp->sign_hash(root.h.data(), root.h.size());

  const auto num_endorsements = rand() % 3;
  for (auto i = 0; i < num_endorsements; ++i)
  {
    auto service_kp = ccf::crypto::make_ec_key_pair();
    auto service_cert =
      service_kp->self_sign("CN=service", valid_from, valid_to);
    const auto csr = node_kp->create_csr(fmt::format("CN=Test{}", i));
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
  REQUIRE(l->node_id == r->node_id);
  REQUIRE(l->cert == r->cert);
  REQUIRE(l->service_endorsements == r->service_endorsements);
  REQUIRE(l->is_signature_transaction() == r->is_signature_transaction());

  if (!l->is_signature_transaction())
  {
    auto p_l = std::dynamic_pointer_cast<ccf::ProofReceipt>(l);
    REQUIRE(p_l != nullptr);

    auto p_r = std::dynamic_pointer_cast<ccf::ProofReceipt>(r);
    REQUIRE(p_r != nullptr);

    REQUIRE(p_l->proof == p_r->proof);
    REQUIRE(
      p_l->leaf_components.write_set_digest ==
      p_r->leaf_components.write_set_digest);
    REQUIRE(
      p_l->leaf_components.commit_evidence ==
      p_r->leaf_components.commit_evidence);
    REQUIRE(
      p_l->leaf_components.claims_digest == p_r->leaf_components.claims_digest);
  }
  else
  {
    throw std::logic_error("Unhandled receipt type");
  }
}

TEST_CASE("JSON parsing" * doctest::test_suite("receipt"))
{
  const auto sample_json_receipt =
    R"xxx({
  "cert": "-----BEGIN CERTIFICATE-----\nMIIBzjCCAVSgAwIBAgIQGR/ue9CFspRa/g6jSMHFYjAKBggqhkjOPQQDAzAWMRQw\nEgYDVQQDDAtDQ0YgTmV0d29yazAeFw0yMjAxMjgxNjAzNDZaFw0yMjAxMjkxNjAz\nNDVaMBMxETAPBgNVBAMMCENDRiBOb2RlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE\nwsdpHLNw7xso/g71XzlQjoITiTBOef8gCayOiPJh/W2YfzreOawzD6gVQPSI+iPg\nZPc6smFhtV5bP/WZ2KW0K9Pn+OIjm/jMU5+s3rSgts50cRjlA/k81bUI88dzQzx9\no2owaDAJBgNVHRMEAjAAMB0GA1UdDgQWBBQgtPwYar54AQ4UL0RImVsm6wQQpzAf\nBgNVHSMEGDAWgBS2ngksRlVPvwDcLhN57VV+j2WyBTAbBgNVHREEFDAShwR/AAAB\nhwR/ZEUlhwR/AAACMAoGCCqGSM49BAMDA2gAMGUCMQDq54yS4Bmfwfcikpy2yL2+\nGFemyqNKXheFExRVt2edxVgId+uvIBGjrJEqf6zS/dsCMHVnBCLYRgxpamFkX1BF\nBDkVitfTOdYfUDWGV3MIMNdbam9BDNxG4q6XtQr4eb3jqg==\n-----END CERTIFICATE-----\n",
  "leaf_components": {
    "commit_evidence": "ce:2.643:55dbbbf04b71c6dcc01dd9d1c0012a6a959aef907398f7e183cc8913c82468d8",
    "write_set_digest": "d0c521504ce2be6b4c22db8e99b14fc475b51bc91224181c75c64aa2cef72b83",
    "claims_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "node_id": "7dfbb9a56ebe8b43c833b34cb227153ef61e4890187fe6164022255dec8f9646",
  "proof": [
    {
      "left": "00a771baf15468ed05d6ef8614b3669fcde6809314650061d64281b5d4faf9ec"
    },
    {
      "left": "a9c8a36d01aa9dfbfb74c6f6a2cef2efcbd92bd6dfd1f7440302ad5ac7be1577"
    },
    {
      "right": "8e238d95767e6ffe4b20e1a5e93dd7b926cbd86caa83698584a16ad2dd7d60b8"
    },
    {
      "left": "d4717996ae906cdce0ac47257a4a9445c58474c2f40811e575f804506e5fee9f"
    },
    {
      "left": "c1c206c4670bd2adee821013695d593f5983ca0994ae74630528da5fb6642205"
    }
  ],
  "service_endorsements": [
    "-----BEGIN CERTIFICATE-----MIIBtTCCATugAwIBAgIRAN37fxGnWYNVLZn8nM8iBP8wCgYIKoZIzj0EAwMwFjEU\nMBIGA1UEAwwLQ0NGIE5ldHdvcmswHhcNMjIwMzIzMTMxMDA2WhcNMjIwMzI0MTMx\nMDA1WjAWMRQwEgYDVQQDDAtDQ0YgTmV0d29yazB2MBAGByqGSM49AgEGBSuBBAAi\nA2IABBErIfAEVg2Uw+iBPV9kEcpQw8NcoZWHmj4boHf7VVd6yCwRl+X/wOaOudca\nCqMMcwrt4Bb7n11RbsRwU04B7fG907MelICFHiPZjU/XMK5HEsSEZWowVtNwOLDo\nl5cN6aNNMEswCQYDVR0TBAIwADAdBgNVHQ4EFgQU4n5gHhHFnYZc3nwxKRggl8YB\nqdgwHwYDVR0jBBgwFoAUcAvR3F5YSUvPPGcAxrvh2Z5ump8wCgYIKoZIzj0EAwMD\naAAwZQIxAMeRoXo9FDzr51qkiD4Ws0Y+KZT06MFHcCg47TMDSGvnGrwL3DcIjGs7\nTTwJJQjbWAIwS9AqOJP24sN6jzXOTd6RokeF/MTGJbQAihzgTbZia7EKM8s/0yDB\n0QYtrfMjtPOx\n-----END CERTIFICATE-----\n"
  ],
  "signature": "MGQCMHrnwS123oHqUKuQRPsQ+gk6WVutixeOvxcXX79InBgPOxJCoScCOlBnK4UYyLzangIwW9k7IZkMgG076qVv5zcx7OuKb7bKyii1yP1rcakeGVvVMwISeE+Fr3BnFfPD66Df",
  "is_signature_transaction": false
})xxx";

  nlohmann::json j = nlohmann::json::parse(sample_json_receipt);

  auto receipt = j.get<ccf::ReceiptPtr>();

  nlohmann::json j2 = receipt;
  REQUIRE(j == j2);

  INFO("Check that old formats, with missing fields, can still be parsed");
  {
    j.erase("service_endorsements");
    auto unendorsed = j.get<ccf::ReceiptPtr>();
    receipt->service_endorsements.clear();
    compare_receipts(receipt, unendorsed);

    j["leaf_components"].erase("claims_digest");
    REQUIRE_NOTHROW(j.get<ccf::ReceiptPtr>());
  }
}

TEST_CASE("JSON roundtrip" * doctest::test_suite("receipt"))
{
  {
    std::shared_ptr<ccf::Receipt> r = nullptr;
    nlohmann::json j;
    REQUIRE_THROWS(to_json(j, r));
    REQUIRE_THROWS(from_json(j, r));
  }

  for (auto i = 0; i < 20; ++i)
  {
    {
      INFO("ProofReceipt");
      auto p_receipt = std::make_shared<ccf::ProofReceipt>();
      p_receipt->leaf_components.write_set_digest = rand_digest();
      p_receipt->leaf_components.commit_evidence = "ce:2.4:abcd";
      p_receipt->leaf_components.claims_digest.set(rand_digest());

      populate_receipt(p_receipt);

      nlohmann::json j = p_receipt;

      const auto parsed = j.get<ccf::ReceiptPtr>();
      compare_receipts(p_receipt, parsed);
    }
  }
}
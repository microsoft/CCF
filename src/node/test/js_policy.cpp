// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "node/js_policy.h"

#include "js/global_class_ids.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

using namespace ccf::policy;
using namespace ccf::cose;

TEST_CASE("Policy error handling")
{
  Sign1ProtectedHeader phdr;
  phdr.alg = -7; // ES256
  phdr.cwt.iss = "did:x509:test-issuer";
  phdr.cwt.sub = "test-subject";
  phdr.cwt.iat = 1700000000;
  phdr.cwt.svn = 42;

  CcfCoseReceiptPhdr rphdr;
  rphdr.alg = -7;
  rphdr.vds = 1;
  rphdr.kid = {'k', 'i', 'd', '1'};
  rphdr.cwt.iss = "did:x509:receipt-issuer";
  rphdr.cwt.sub = "receipt-subject";
  rphdr.cwt.iat = 1700000001;
  rphdr.ccf.txid = "2.42";

  Leaf leaf;
  leaf.claims_digest = {0xab, 0xcd, 0xef};
  leaf.commit_evidence = "ce:2.42:deadbeef";
  leaf.write_set_digest = {0x01, 0x02, 0x03};

  ReceiptPolicyInput receipt;
  receipt.phdr = rphdr;
  receipt.leaves.push_back(leaf);

  TransparentStatementPolicyInput input;
  input.phdr = phdr;
  input.receipts.push_back(receipt);

  std::vector<TransparentStatementPolicyInput> inputs;
  inputs.push_back(input);

  SUBCASE("Returns true accepts")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return true;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE_FALSE(result.has_value());
  }

  SUBCASE("Returns string rejects with that reason")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return "rejected for testing";
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == "rejected for testing");
  }

  SUBCASE("Returns false gives unexpected return value")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return false;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Unexpected return value") != std::string::npos);
  }

  SUBCASE("Returns undefined gives unexpected return value")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return undefined;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Unexpected return value") != std::string::npos);
  }

  SUBCASE("Returns null gives unexpected return value")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return null;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Unexpected return value") != std::string::npos);
  }

  SUBCASE("Returns number gives unexpected return value")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return 42;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Unexpected return value") != std::string::npos);
  }

  SUBCASE("Throws is reported as error")
  {
    const std::string policy = R"(
      export function apply(statements) {
        throw new Error("intentional failure");
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Code update policy threw") != std::string::npos);
    REQUIRE(result.value().find("intentional failure") != std::string::npos);
  }

  SUBCASE("Syntax error")
  {
    const std::string policy = R"(
      export function apply(statements {
        return true;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Invalid code update policy module") !=
      std::string::npos);
  }

  SUBCASE("Missing apply export")
  {
    const std::string policy = R"(
      export function validate(statements) {
        return true;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Invalid code update policy module") !=
      std::string::npos);
  }

  SUBCASE("Empty policy string")
  {
    const std::string policy;
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Invalid code update policy module") !=
      std::string::npos);
  }

  SUBCASE("Runtime error in JS")
  {
    const std::string policy = R"(
      export function apply(statements) {
        return statements[99].phdr.alg;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Code update policy threw") != std::string::npos);
  }

  SUBCASE("Infinite loop is handled")
  {
    const std::string policy = R"(
      export function apply(statements) {
        while (true) {}
        return true;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(
      result.value().find("Code update policy threw") != std::string::npos);
  }

  SUBCASE("Empty inputs")
  {
    inputs.clear();
    const std::string policy = R"(
      export function apply(statements) {
        if (statements.length === 0) return "no statements provided";
        return true;
      }
    )";
    auto result = apply_node_join_policy(policy, inputs);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == "no statements provided");
  }
}

TEST_CASE("Comprehensive policy verifies 2 TSs with 2 receipts each")
{
  // TS 1: cty as string, two receipts with distinct values
  TransparentStatementPolicyInput ts1;
  ts1.phdr.alg = -7;
  ts1.phdr.cwt.iss = "did:x509:issuer-1";
  ts1.phdr.cwt.sub = "subject-1";
  ts1.phdr.cwt.iat = 1700000000;
  ts1.phdr.cwt.svn = 10;
  ts1.phdr.cty = std::string("application/json");

  {
    ReceiptPolicyInput r;
    r.phdr.alg = -7;
    r.phdr.vds = 1;
    r.phdr.kid = {'k', '1'};
    r.phdr.cwt.iss = "did:x509:receipt-1a";
    r.phdr.cwt.sub = "receipt-sub-1a";
    r.phdr.cwt.iat = 1700000001;
    r.phdr.ccf.txid = "2.10";
    Leaf l;
    l.claims_digest = {0xaa};
    l.commit_evidence = "ce:2.10:aaa";
    l.write_set_digest = {0x01};
    r.leaves.push_back(l);
    ts1.receipts.push_back(r);
  }
  {
    ReceiptPolicyInput r;
    r.phdr.alg = -35;
    r.phdr.vds = 2;
    r.phdr.kid = {'k', '2'};
    r.phdr.cwt.iss = "did:x509:receipt-1b";
    r.phdr.cwt.sub = "receipt-sub-1b";
    r.phdr.cwt.iat = 1700000002;
    r.phdr.ccf.txid = "2.20";
    Leaf l;
    l.claims_digest = {0xbb, 0xcc};
    l.commit_evidence = "ce:2.20:bbb";
    l.write_set_digest = {0x02, 0x03};
    r.leaves.push_back(l);
    ts1.receipts.push_back(r);
  }

  // TS 2: cty as integer, two receipts
  TransparentStatementPolicyInput ts2;
  ts2.phdr.alg = -35;
  ts2.phdr.cwt.iss = "did:x509:issuer-2";
  ts2.phdr.cwt.sub = "subject-2";
  ts2.phdr.cwt.iat = 1700001000;
  ts2.phdr.cwt.svn = 20;
  ts2.phdr.cty = int64_t(99);

  {
    ReceiptPolicyInput r;
    r.phdr.alg = -7;
    r.phdr.vds = 1;
    r.phdr.kid = {'k', '3'};
    r.phdr.cwt.iss = "did:x509:receipt-2a";
    r.phdr.cwt.sub = "receipt-sub-2a";
    r.phdr.cwt.iat = 1700001001;
    r.phdr.ccf.txid = "3.30";
    Leaf l;
    l.claims_digest = {0xdd};
    l.commit_evidence = "ce:3.30:ccc";
    l.write_set_digest = {0x04};
    r.leaves.push_back(l);
    ts2.receipts.push_back(r);
  }
  {
    ReceiptPolicyInput r;
    r.phdr.alg = -35;
    r.phdr.vds = 2;
    r.phdr.kid = {'k', '4'};
    r.phdr.cwt.iss = "did:x509:receipt-2b";
    r.phdr.cwt.sub = "receipt-sub-2b";
    r.phdr.cwt.iat = 1700001002;
    r.phdr.ccf.txid = "3.40";
    Leaf l;
    l.claims_digest = {0xee, 0xff};
    l.commit_evidence = "ce:3.40:ddd";
    l.write_set_digest = {0x05, 0x06};
    r.leaves.push_back(l);
    ts2.receipts.push_back(r);
  }

  std::vector<TransparentStatementPolicyInput> inputs = {ts1, ts2};

  const std::string policy = R"(
    export function apply(statements) {
      if (statements.length !== 2) return "expected 2 statements";

      // TS 1
      const s0 = statements[0];
      if (s0.phdr.alg !== -7) return "s0: wrong alg";
      if (s0.phdr.cwt.iss !== "did:x509:issuer-1") return "s0: wrong iss";
      if (s0.phdr.cwt.sub !== "subject-1") return "s0: wrong sub";
      if (s0.phdr.cwt.iat !== 1700000000) return "s0: wrong iat";
      if (s0.phdr.cwt.svn !== 10) return "s0: wrong svn";
      if (s0.phdr.cty !== "application/json") return "s0: wrong cty";
      if (s0.receipts.length !== 2) return "s0: expected 2 receipts";

      const r00 = s0.receipts[0];
      if (r00.alg !== -7) return "r00: wrong alg";
      if (r00.vds !== 1) return "r00: wrong vds";
      if (r00.kid !== "k1") return "r00: wrong kid";
      if (r00.cwt.iss !== "did:x509:receipt-1a") return "r00: wrong iss";
      if (r00.cwt.sub !== "receipt-sub-1a") return "r00: wrong sub";
      if (r00.cwt.iat !== 1700000001) return "r00: wrong iat";
      if (r00.ccf.txid !== "2.10") return "r00: wrong txid";
      if (r00.leaves.length !== 1) return "r00: expected 1 leaf";
      if (r00.leaves[0].claims_digest !== "aa") return "r00: wrong claims_digest";
      if (r00.leaves[0].commit_evidence !== "ce:2.10:aaa") return "r00: wrong commit_evidence";
      if (r00.leaves[0].write_set_digest !== "01") return "r00: wrong write_set_digest";

      const r01 = s0.receipts[1];
      if (r01.alg !== -35) return "r01: wrong alg";
      if (r01.vds !== 2) return "r01: wrong vds";
      if (r01.kid !== "k2") return "r01: wrong kid";
      if (r01.cwt.iss !== "did:x509:receipt-1b") return "r01: wrong iss";
      if (r01.cwt.sub !== "receipt-sub-1b") return "r01: wrong sub";
      if (r01.cwt.iat !== 1700000002) return "r01: wrong iat";
      if (r01.ccf.txid !== "2.20") return "r01: wrong txid";
      if (r01.leaves[0].claims_digest !== "bbcc") return "r01: wrong claims_digest";
      if (r01.leaves[0].commit_evidence !== "ce:2.20:bbb") return "r01: wrong commit_evidence";
      if (r01.leaves[0].write_set_digest !== "0203") return "r01: wrong write_set_digest";

      // TS 2
      const s1 = statements[1];
      if (s1.phdr.alg !== -35) return "s1: wrong alg";
      if (s1.phdr.cwt.iss !== "did:x509:issuer-2") return "s1: wrong iss";
      if (s1.phdr.cwt.sub !== "subject-2") return "s1: wrong sub";
      if (s1.phdr.cwt.iat !== 1700001000) return "s1: wrong iat";
      if (s1.phdr.cwt.svn !== 20) return "s1: wrong svn";
      if (s1.phdr.cty !== 99) return "s1: wrong cty";
      if (s1.receipts.length !== 2) return "s1: expected 2 receipts";

      const r10 = s1.receipts[0];
      if (r10.alg !== -7) return "r10: wrong alg";
      if (r10.vds !== 1) return "r10: wrong vds";
      if (r10.kid !== "k3") return "r10: wrong kid";
      if (r10.cwt.iss !== "did:x509:receipt-2a") return "r10: wrong iss";
      if (r10.cwt.sub !== "receipt-sub-2a") return "r10: wrong sub";
      if (r10.cwt.iat !== 1700001001) return "r10: wrong iat";
      if (r10.ccf.txid !== "3.30") return "r10: wrong txid";
      if (r10.leaves[0].claims_digest !== "dd") return "r10: wrong claims_digest";
      if (r10.leaves[0].commit_evidence !== "ce:3.30:ccc") return "r10: wrong commit_evidence";
      if (r10.leaves[0].write_set_digest !== "04") return "r10: wrong write_set_digest";

      const r11 = s1.receipts[1];
      if (r11.alg !== -35) return "r11: wrong alg";
      if (r11.vds !== 2) return "r11: wrong vds";
      if (r11.kid !== "k4") return "r11: wrong kid";
      if (r11.cwt.iss !== "did:x509:receipt-2b") return "r11: wrong iss";
      if (r11.cwt.sub !== "receipt-sub-2b") return "r11: wrong sub";
      if (r11.cwt.iat !== 1700001002) return "r11: wrong iat";
      if (r11.ccf.txid !== "3.40") return "r11: wrong txid";
      if (r11.leaves[0].claims_digest !== "eeff") return "r11: wrong claims_digest";
      if (r11.leaves[0].commit_evidence !== "ce:3.40:ddd") return "r11: wrong commit_evidence";
      if (r11.leaves[0].write_set_digest !== "0506") return "r11: wrong write_set_digest";

      return true;
    }
  )";

  auto result = apply_node_join_policy(policy, inputs);
  REQUIRE_FALSE(result.has_value());
}

TEST_CASE("Optional fields are undefined when absent")
{
  TransparentStatementPolicyInput input;
  input.phdr.alg = -7;
  input.phdr.cwt.iss = "test";
  input.phdr.cwt.sub = "test";
  // No cty, no svn, no iat

  ReceiptPolicyInput receipt;
  receipt.phdr.alg = -7;
  receipt.phdr.vds = 1;
  // No kid, no cwt fields, no ccf.txid

  Leaf leaf;
  // No claims_digest, no commit_evidence, no write_set_digest
  receipt.leaves.push_back(leaf);
  input.receipts.push_back(receipt);

  std::vector<TransparentStatementPolicyInput> inputs;
  inputs.push_back(input);

  const std::string policy = R"(
    export function apply(statements) {
      const s = statements[0];
      if (s.phdr.cty !== undefined) return "cty should be absent";
      if (s.phdr.cwt.svn !== undefined) return "svn should be absent";
      if (s.phdr.cwt.iat !== undefined) return "iat should be absent";

      const r = s.receipts[0];
      if (r.kid !== undefined) return "kid should be absent";
      if (r.cwt.iss !== undefined) return "iss should be absent";
      if (r.cwt.sub !== undefined) return "sub should be absent";
      if (r.cwt.iat !== undefined) return "iat should be absent";
      if (r.ccf.txid !== undefined) return "txid should be absent";

      return true;
    }
  )";

  auto result = apply_node_join_policy(policy, inputs);
  REQUIRE_FALSE(result.has_value());
}

int main(int argc, char** argv)
{
  ccf::js::register_class_ids();

  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  if (context.shouldExit())
    return res;
  return res;
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../proposals.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

TEST_CASE("OpenProposal")
{
  using namespace ccf;

  // Construct proposals
  OpenProposal op0;

  Script script0("return true");
  nlohmann::json param0("hello world");
  MemberId member0(0);
  OpenProposal op1(script0, param0, member0);

  // Check they're distinct
  CHECK(!(op0 == op1));

  // Serialize
  msgpack::sbuffer sb0;
  msgpack::pack(sb0, op0);

  msgpack::sbuffer sb1;
  msgpack::pack(sb1, op1);

  // Deserialize
  msgpack::object_handle obj0;
  msgpack::unpack(obj0, sb0.data(), sb0.size(), 0);
  OpenProposal _op0 = obj0->convert();

  msgpack::object_handle obj1;
  msgpack::unpack(obj1, sb1.data(), sb1.size(), 0);
  OpenProposal _op1 = obj1->convert();

  // Check deserializations are correct
  CHECK(op0 == _op0);
  CHECK(op1 == _op1);
}

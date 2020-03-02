// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../members.h"
#include "../proposals.h"
#include "../signatures.h"

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

template <typename T>
T msgpack_roundtrip(const T& t)
{
  // Serialize
  msgpack::sbuffer sb;
  msgpack::pack(sb, t);

  // Deserialize
  msgpack::object_handle obj;
  msgpack::unpack(obj, sb.data(), sb.size(), 0);

  return obj->as<T>();
}

TEST_CASE("nlohmann::json")
{
  using namespace nlohmann;

  json j_null = nullptr;
  {
    const auto converted = msgpack_roundtrip(j_null);
    CHECK(j_null == converted);
  }

  json j_int = 42;
  {
    const auto converted = msgpack_roundtrip(j_int);
    CHECK(j_int == converted);
  }

  json j_float = 3.14f;
  {
    const auto converted = msgpack_roundtrip(j_float);
    CHECK(j_float == converted);
  }

  json j_string = "hello world";
  {
    const auto converted = msgpack_roundtrip(j_string);
    CHECK(j_string == converted);
  }

  json j_array = json::array();
  j_array.push_back(j_null);
  j_array.push_back(j_int);
  j_array.push_back(j_float);
  j_array.push_back(j_string);
  {
    const auto converted = msgpack_roundtrip(j_array);
    CHECK(j_array == converted);
  }

  json j_object = json::object();
  j_object["A"] = j_array;
  j_object["saluton mondo"] = j_string;
  {
    const auto converted = msgpack_roundtrip(j_object);
    CHECK(j_object == converted);
  }
}

TEST_CASE("Proposal")
{
  using namespace ccf;

  {
    INFO("Empty proposal");
    Proposal proposal;
    const auto converted = msgpack_roundtrip(proposal);
    CHECK(proposal == converted);
  }

  {
    INFO("Initial proposal");
    Script s("return true");
    nlohmann::json p("hello world");
    MemberId m(0);
    Proposal proposal(s, p, m);
    const auto converted = msgpack_roundtrip(proposal);
    CHECK(proposal == converted);
  }

  {
    INFO("Voted proposal");
    Script s("return true");
    nlohmann::json p("hello world");
    MemberId m(0);
    Proposal proposal(s, p, m);
    proposal.votes[1] = Script("return true");
    proposal.votes[2] = Script("return false");
    proposal.votes[3] = Script("return RoN");
    proposal.votes[4] = Script("Robert'); DROP TABLE Students;--");
    const auto converted = msgpack_roundtrip(proposal);
    CHECK(proposal == converted);
  }
}

void fill_rand(std::vector<uint8_t>& v, size_t n)
{
  v.resize(n);
  for (size_t i = 0; i < n; ++i)
  {
    v[i] = rand();
  }
}

TEST_CASE("RawSignature")
{
  using namespace ccf;

  {
    INFO("Empty signature");
    RawSignature rs;
    const auto converted = msgpack_roundtrip(rs);
    CHECK(rs == converted);
  }

  {
    INFO("Byte signature");
    RawSignature rs;
    rs.sig.push_back(42);
    const auto converted = msgpack_roundtrip(rs);
    CHECK(rs == converted);
  }

  {
    INFO("Large signature");
    RawSignature rs;
    fill_rand(rs.sig, 256);
    const auto converted = msgpack_roundtrip(rs);
    CHECK(rs == converted);
  }
}

TEST_CASE("MemberAck")
{
  using namespace ccf;

  {
    INFO("Empty ack");
    MemberAck ma;
    const auto converted = msgpack_roundtrip(ma);
    CHECK(ma.state_digest == converted.state_digest);
  }

  {
    INFO("Implausible ack");
    MemberAck ma;
    ma.state_digest.push_back(42);
    const auto converted = msgpack_roundtrip(ma);
    CHECK(ma.state_digest == converted.state_digest);
  }

  {
    INFO("Plausible ack");
    MemberAck ma;
    fill_rand(ma.state_digest, 16);
    const auto converted = msgpack_roundtrip(ma);
    CHECK(ma.state_digest == converted.state_digest);
  }
}

TEST_CASE("Signature")
{
  using namespace ccf;

  {
    INFO("Empty sig");
    Signature sig;
    const auto converted = msgpack_roundtrip(sig);
    CHECK(sig == converted);
  }

  {
    INFO("Simple sig");
    Signature sig;
    sig.sig.push_back(0);
    sig.node = 0;
    sig.index = 1;
    sig.term = 2;
    sig.commit = 3;
    const auto converted = msgpack_roundtrip(sig);
    CHECK(sig == converted);
  }

  {
    INFO("Rand sig");
    Signature sig;
    fill_rand(sig.sig, 256);
    sig.node = rand();
    sig.index = rand();
    sig.term = rand();
    sig.commit = rand();
    const auto converted = msgpack_roundtrip(sig);
    CHECK(sig == converted);
  }
}

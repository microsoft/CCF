// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "enclave/appinterface.h"
#include "kv/kv.h"
#include "kv/kvserialiser.h"
#include "node/encryptor.h"
#include "stub_consensus.h"

#include <doctest/doctest.h>
#include <msgpack-c/msgpack.hpp>
#include <string>
#include <vector>

using namespace ccfapp;

struct CustomClass
{
  int m_i;

  CustomClass() : CustomClass(-1) {}
  CustomClass(int i) : m_i(i) {}

  int get() const
  {
    return m_i;
  }
  void set(std::string val)
  {
    m_i = std::stoi(val);
  }

  CustomClass operator()()
  {
    CustomClass ret;
    return ret;
  }

  bool operator<(const CustomClass& other) const
  {
    return m_i < other.m_i;
  }

  bool operator==(const CustomClass& other) const
  {
    return !(other < *this) && !(*this < other);
  }

  MSGPACK_DEFINE(m_i);
};

namespace std
{
  template <>
  struct hash<CustomClass>
  {
    std::size_t operator()(const CustomClass& inst) const
    {
      return inst.get();
    }
  };
}

DECLARE_JSON_TYPE(CustomClass)
DECLARE_JSON_REQUIRED_FIELDS(CustomClass, m_i)

TEST_CASE(
  "Serialise/deserialise public map only" *
  doctest::test_suite("serialisation"))
{
  // No need for an encryptor here as all maps are public. Both serialisation
  // and deserialisation should succeed.
  auto consensus = std::make_shared<kv::StubConsensus>();

  Store kv_store(consensus);
  Store kv_store_target;

  auto& pub_map = kv_store.create<std::string, std::string>(
    "pub_map", kv::SecurityDomain::PUBLIC);
  kv_store_target.clone_schema(kv_store);

  INFO("Commit to public map in source store");
  {
    Store::Tx tx;
    auto view0 = tx.get_view(pub_map);
    view0->put("pubk1", "pubv1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Deserialise transaction in target store");
  {
    REQUIRE(
      kv_store_target.deserialise(consensus->get_latest_data().first) ==
      kv::DeserialiseSuccess::PASS);

    Store::Tx tx_target;
    auto view_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("pub_map"));
    REQUIRE(view_target->get("pubk1") == "pubv1");
  }
}

TEST_CASE(
  "Serialise/deserialise private map only" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();

  Store kv_store(consensus);
  Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  auto& priv_map = kv_store.create<std::string, std::string>(
    "priv_map", kv::SecurityDomain::PRIVATE);
  kv_store_target.clone_schema(kv_store);

  INFO("Commit a private transaction without an encryptor throws an exception");
  {
    Store::Tx tx;
    auto view0 = tx.get_view(priv_map);
    view0->put("privk1", "privv1");
    REQUIRE_THROWS_AS(tx.commit(), kv::KvSerialiserException);
  }

  // Since a serialisation error occurred and was not recovered properly (see
  // https://github.com/microsoft/CCF/issues/338), we need to clear the store to
  // get a fresh version.
  kv_store.clear();
  kv_store.set_encryptor(encryptor);

  INFO("Commit to private map in source store");
  {
    Store::Tx tx;
    auto view0 = tx.get_view(priv_map);
    view0->put("privk1", "privv1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Deserialise transaction in target store");
  {
    REQUIRE(
      kv_store_target.deserialise(consensus->get_latest_data().first) ==
      kv::DeserialiseSuccess::PASS);

    Store::Tx tx_target;
    auto view_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("priv_map"));
    REQUIRE(view_target->get("privk1") == "privv1");
  }
}

TEST_CASE(
  "Serialise/deserialise private and public maps" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();

  Store kv_store(consensus);
  Store kv_store_target;
  kv_store.set_encryptor(encryptor);
  kv_store_target.set_encryptor(encryptor);

  auto& priv_map = kv_store.create<std::string, std::string>("priv_map");
  auto& pub_map = kv_store.create<std::string, std::string>(
    "pub_map", kv::SecurityDomain::PUBLIC);
  kv_store_target.clone_schema(kv_store);

  INFO("Commit to public and private map in source store");
  {
    Store::Tx tx;
    auto [view_priv, view_pub] = tx.get_view(priv_map, pub_map);

    view_priv->put("privk1", "privv1");
    view_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Deserialise transaction in target store");
  {
    auto serial = consensus->get_latest_data();
    REQUIRE(
      kv_store_target.deserialise(serial.first) !=
      kv::DeserialiseSuccess::FAILED);

    Store::Tx tx;
    auto [view_priv, view_pub] = tx.get_view(
      *kv_store_target.get<std::string, std::string>("priv_map"),
      *kv_store_target.get<std::string, std::string>("pub_map"));

    REQUIRE(view_priv->get("privk1") == "privv1");
    REQUIRE(view_pub->get("pubk1") == "pubv1");
  }
}

TEST_CASE(
  "Serialise/deserialise removed keys" * doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();

  Store kv_store(consensus);
  Store kv_store_target;
  kv_store.set_encryptor(encryptor);
  kv_store_target.set_encryptor(encryptor);

  auto& priv_map = kv_store.create<std::string, std::string>("priv_map");
  kv_store_target.clone_schema(kv_store);

  INFO("Commit a new key in source store and deserialise in target store");
  {
    Store::Tx tx;
    auto view_priv = tx.get_view(priv_map);
    view_priv->put("privk1", "privv1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    auto serial = consensus->get_latest_data();
    REQUIRE(
      kv_store_target.deserialise(serial.first) !=
      kv::DeserialiseSuccess::FAILED);

    Store::Tx tx_target;
    auto view_priv_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("priv_map"));
    REQUIRE(view_priv_target->get("privk1") == "privv1");
  }

  INFO("Commit key removal in source store and deserialise in target store");
  {
    Store::Tx tx;
    auto view_priv = tx.get_view(priv_map);
    view_priv->remove("privk1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    // Make sure it has been marked as deleted in source store
    Store::Tx tx2;
    auto view_priv2 = tx2.get_view(priv_map);
    REQUIRE(view_priv2->get("privk1").has_value() == false);

    auto serial = consensus->get_latest_data();
    REQUIRE(
      kv_store_target.deserialise(serial.first) !=
      kv::DeserialiseSuccess::FAILED);

    Store::Tx tx_target;
    auto view_priv_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("priv_map"));
    REQUIRE(view_priv_target->get("privk1").has_value() == false);
  }
}

TEST_CASE(
  "Custom type serialisation test" * doctest::test_suite("serialisation"))
{
  Store kv_store;

  auto& map = kv_store.create<CustomClass, CustomClass>(
    "map", kv::SecurityDomain::PUBLIC);

  CustomClass k(3);
  CustomClass v1(33);

  CustomClass k2(2);
  CustomClass v2(22);

  INFO("Serialise/Deserialise 2 kv stores");
  {
    Store kv_store2;
    auto& map2 = kv_store2.create<CustomClass, CustomClass>(
      "map", kv::SecurityDomain::PUBLIC);

    Store::Tx tx(kv_store.next_version());
    auto view = tx.get_view(map);
    view->put(k, v1);
    view->put(k2, v2);

    auto [success, reqid, serialised] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);
    kv_store.compact(view->end_order());

    REQUIRE(kv_store2.deserialise(serialised) == kv::DeserialiseSuccess::PASS);
    Store::Tx tx2;
    auto view2 = tx2.get_view(map2);
    auto va = view2->get(k);

    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    auto vb = view2->get(k2);
    REQUIRE(vb.has_value());
    REQUIRE(vb.value() == v2);
    // we only require operator==() to be implemented, so for consistency -
    // this is the operator we use for comparison, and not operator!=()
    REQUIRE(!(vb.value() == v1));
  }
}

bool corrupt_serialised_tx(
  std::vector<uint8_t>& serialised_tx, std::vector<uint8_t>& value_to_corrupt)
{
  // This utility function corrupts a serialised transaction by changing one
  // byte of the public domain as specified by value_to_corrupt.
  std::vector<uint8_t> match_buffer;
  for (auto& i : serialised_tx)
  {
    if (i == value_to_corrupt[match_buffer.size()])
    {
      match_buffer.push_back(i);
      if (match_buffer.size() == value_to_corrupt.size())
      {
        i = 'X';
        LOG_DEBUG_FMT("Corrupting serialised public data");
        return true;
      }
    }
    else
    {
      match_buffer.clear();
    }
  }
  return false;
}

TEST_CASE("Integrity" * doctest::test_suite("serialisation"))
{
  SUBCASE("Public and Private")
  {
    auto consensus = std::make_shared<kv::StubConsensus>();

    // Here, a real encryptor is needed to protect the integrity of the
    // transactions
    auto secrets = ccf::NetworkSecrets("");
    auto encryptor = std::make_shared<ccf::TxEncryptor>(1, secrets);

    Store kv_store(consensus);
    Store kv_store_target;
    kv_store.set_encryptor(encryptor);
    kv_store_target.set_encryptor(encryptor);

    auto& public_map = kv_store.create<std::string, std::string>(
      "public_map", kv::SecurityDomain::PUBLIC);
    auto& private_map = kv_store.create<std::string, std::string>(
      "private_map", kv::SecurityDomain::PRIVATE);

    kv_store_target.clone_schema(kv_store);

    Store::Tx tx;
    auto [public_view, private_view] = tx.get_view(public_map, private_map);
    std::string pub_value = "pubv1";
    public_view->put("pubk1", pub_value);
    private_view->put("privk1", "privv1");
    auto rc = tx.commit();

    // Tamper with serialised public data
    auto serialised_tx = consensus->get_latest_data().first;
    std::vector<uint8_t> value_to_corrupt(pub_value.begin(), pub_value.end());
    REQUIRE(corrupt_serialised_tx(serialised_tx, value_to_corrupt));

    REQUIRE(
      kv_store_target.deserialise(serialised_tx) ==
      kv::DeserialiseSuccess::FAILED);
  }
}

TEST_CASE("nlohmann (de)serialisation" * doctest::test_suite("serialisation"))
{
  const auto k0 = "abc";
  const auto v0 = 123;

  const std::vector<int> k1{4, 5, 6, 7};
  const std::string v1 = "xyz";

  SUBCASE("baseline")
  {
    auto r = std::make_shared<kv::StubConsensus>();
    using Table = Store::Map<std::vector<int>, std::string>;
    Store s0(r), s1;
    auto& t = s0.create<Table>("t", kv::SecurityDomain::PUBLIC);
    s1.create<Table>("t");

    Store::Tx tx;
    tx.get_view(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(
      s1.deserialise(r->get_latest_data().first) !=
      kv::DeserialiseSuccess::FAILED);
  }

  SUBCASE("nlohmann")
  {
    auto r = std::make_shared<kv::StubConsensus>();
    using Table = Store::Map<nlohmann::json, nlohmann::json>;
    Store s0(r), s1;
    auto& t = s0.create<Table>("t", kv::SecurityDomain::PUBLIC);
    s1.create<Table>("t");

    Store::Tx tx;
    tx.get_view(t)->put(k0, v0);
    tx.get_view(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(
      s1.deserialise(r->get_latest_data().first) !=
      kv::DeserialiseSuccess::FAILED);
  }
}

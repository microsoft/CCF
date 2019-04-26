// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "../../ds/logger.h"
#include "../../enclave/appinterface.h"
#include "../../node/encryptor.h"
#include "../kvserialiser.h"
#include "../kv.h"
#include "../replicator.h"

#include <doctest/doctest.h>
#include <msgpack-c/msgpack.hpp>
#include <string>
#include <vector>

using namespace ccfapp;

TEST_CASE("Serialise/deserialise public map only")
{
  auto replicator = std::make_shared<kv::StubReplicator>();
  auto secrets = ccf::NetworkSecrets("");
  auto encryptor = std::make_shared<ccf::TxEncryptor>(1, secrets);

  Store kv_store(replicator);
  Store kv_store_target;
  kv_store.set_encryptor(encryptor);
  kv_store_target.set_encryptor(encryptor);

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
      kv_store_target.deserialise(replicator->get_latest_data().first) ==
      kv::DeserialiseSuccess::PASS);

    Store::Tx tx_target;
    auto view_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("pub_map"));
    REQUIRE(view_target->get("pubk1") == "pubv1");
  }
}

TEST_CASE("Serialise/deserialise private map only")
{
  auto replicator = std::make_shared<kv::StubReplicator>();
  auto secrets = ccf::NetworkSecrets("");
  auto encryptor = std::make_shared<ccf::TxEncryptor>(1, secrets);

  Store kv_store(replicator);
  Store kv_store_target;
  kv_store.set_encryptor(encryptor);
  kv_store_target.set_encryptor(encryptor);

  auto& priv_map = kv_store.create<std::string, std::string>(
    "priv_map", kv::SecurityDomain::PRIVATE);
  kv_store_target.clone_schema(kv_store);

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
      kv_store_target.deserialise(replicator->get_latest_data().first) ==
      kv::DeserialiseSuccess::PASS);

    Store::Tx tx_target;
    auto view_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("priv_map"));
    REQUIRE(view_target->get("privk1") == "privv1");
  }
}

TEST_CASE("Serialise/deserialise private and public maps")
{
  auto replicator = std::make_shared<kv::StubReplicator>();
  auto secrets = ccf::NetworkSecrets("");
  auto encryptor = std::make_shared<ccf::TxEncryptor>(1, secrets);

  Store kv_store(replicator);
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
    auto serial = replicator->get_latest_data();
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

TEST_CASE("Serialise/deserialise removed keys")
{
  auto replicator = std::make_shared<kv::StubReplicator>();
  auto secrets = ccf::NetworkSecrets("");
  auto encryptor = std::make_shared<ccf::TxEncryptor>(1, secrets);

  Store kv_store(replicator);
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

    auto serial = replicator->get_latest_data();
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

    auto serial = replicator->get_latest_data();
    REQUIRE(
      kv_store_target.deserialise(serial.first) !=
      kv::DeserialiseSuccess::FAILED);

    Store::Tx tx_target;
    auto view_priv_target = tx_target.get_view(
      *kv_store_target.get<std::string, std::string>("priv_map"));
    REQUIRE(view_priv_target->get("privk1").has_value() == false);
  }
}

TEST_CASE("Serialise private map with no encryptor/Deserialise in new store")
{
  // This test mirrors the behaviour of the genesisgenerator utility which does
  // not have an encryptor and serialise all maps as if they were public.
  auto replicator = std::make_shared<kv::StubReplicator>();
  Store kv_store(replicator);

  auto& map = kv_store.create<std::string, std::string>("map");

  constexpr auto k = "key";
  constexpr auto k2 = "key2";
  constexpr auto v1 = "value1";
  constexpr auto v2 = "value2";

  INFO("Serialise single transaction");
  {
    Store::Tx tx;
    auto view = tx.get_view(map);
    view->put(k, v1);
    view->put(k2, v2);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Deserialise transaction in new kv store");
  {
    Store kv_store2;
    auto& map2 = kv_store2.create<std::string, std::string>("map");

    auto serial = replicator->get_latest_data();
    REQUIRE(replicator->number_of_replicas() == 1);
    REQUIRE(serial.second);
    REQUIRE(!serial.first.empty());

    Store::Tx tx;
    REQUIRE(
      kv_store2.deserialise(serial.first) != kv::DeserialiseSuccess::FAILED);
    auto view2 = tx.get_view(map2);
    auto va = view2->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    auto vb = view2->get(k2);
    REQUIRE(vb.has_value());
    REQUIRE(vb.value() == v2);
    replicator->flush();
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
        LOG_DEBUG << "Corrupting serialised public data" << std::endl;
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

TEST_CASE("Integrity")
{
  SUBCASE("Public and Private")
  {
    auto replicator = std::make_shared<kv::StubReplicator>();

    auto secrets = ccf::NetworkSecrets("");
    auto encryptor = std::make_shared<ccf::TxEncryptor>(1, secrets);

    Store kv_store(replicator);
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
    auto serialised_tx = replicator->get_latest_data().first;
    std::vector<uint8_t> value_to_corrupt(pub_value.begin(), pub_value.end());
    REQUIRE(corrupt_serialised_tx(serialised_tx, value_to_corrupt));

    REQUIRE(
      kv_store_target.deserialise(serialised_tx) ==
      kv::DeserialiseSuccess::FAILED);
  }
}

TEST_CASE("nlohmann (de)serialisation")
{
  const auto k0 = "abc";
  const auto v0 = 123;

  const std::vector<int> k1{4, 5, 6, 7};
  const std::string v1 = "xyz";

  SUBCASE("baseline")
  {
    auto r = std::make_shared<kv::StubReplicator>();
    using Table = Store::Map<std::vector<int>, std::string>;
    Store s0(r), s1;
    auto& t = s0.create<Table>("t");
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
    auto r = std::make_shared<kv::StubReplicator>();
    using Table = Store::Map<nlohmann::json, nlohmann::json>;
    Store s0(r), s1;
    auto& t = s0.create<Table>("t");
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

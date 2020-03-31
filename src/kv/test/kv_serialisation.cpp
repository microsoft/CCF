// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "consensus/test/stub_consensus.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"
#include "kv/kv.h"
#include "kv/kv_serialiser.h"
#include "node/encryptor.h"

#include <doctest/doctest.h>
#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

using namespace ccf;

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

  auto& priv_map = kv_store.create<std::string, std::string>("priv_map");
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
    REQUIRE(
      kv_store_target.deserialise(consensus->get_latest_data().first) !=
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

    REQUIRE(
      kv_store_target.deserialise(consensus->get_latest_data().first) !=
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

    REQUIRE(
      kv_store_target.deserialise(consensus->get_latest_data().first) !=
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

    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);
    kv_store.compact(view->end_order());

    REQUIRE(kv_store2.deserialise(data) == kv::DeserialiseSuccess::PASS);
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
    auto secrets = std::make_shared<ccf::LedgerSecrets>();
    secrets->set_secret(1, std::vector<uint8_t>(16, 0x42));
    auto encryptor = std::make_shared<ccf::RaftTxEncryptor>(1, secrets);

    Store kv_store(consensus);
    Store kv_store_target;
    kv_store.set_encryptor(encryptor);
    kv_store_target.set_encryptor(encryptor);

    auto& public_map = kv_store.create<std::string, std::string>(
      "public_map", kv::SecurityDomain::PUBLIC);
    auto& private_map =
      kv_store.create<std::string, std::string>("private_map");

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
    auto consensus = std::make_shared<kv::StubConsensus>();
    using Table = Store::Map<std::vector<int>, std::string>;
    Store s0(consensus), s1;
    auto& t = s0.create<Table>("t", kv::SecurityDomain::PUBLIC);
    s1.create<Table>("t");

    Store::Tx tx;
    tx.get_view(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(
      s1.deserialise(consensus->get_latest_data().first) !=
      kv::DeserialiseSuccess::FAILED);
  }

  SUBCASE("nlohmann")
  {
    auto consensus = std::make_shared<kv::StubConsensus>();
    using Table = Store::Map<nlohmann::json, nlohmann::json>;
    Store s0(consensus), s1;
    auto& t = s0.create<Table>("t", kv::SecurityDomain::PUBLIC);
    s1.create<Table>("t");

    Store::Tx tx;
    tx.get_view(t)->put(k0, v0);
    tx.get_view(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    REQUIRE(
      s1.deserialise(consensus->get_latest_data().first) !=
      kv::DeserialiseSuccess::FAILED);
  }
}

TEST_CASE("replicated and derived table serialisation")
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  std::unordered_set<std::string> replicated_tables = {
    "data_replicated", "data_replicated_private"};
  Store store(kv::ReplicateType::SOME, replicated_tables);
  store.set_encryptor(encryptor);

  Store second_store(kv::ReplicateType::SOME, replicated_tables);
  second_store.set_encryptor(encryptor);

  auto& data_replicated =
    store.create<size_t, size_t>("data_replicated", kv::SecurityDomain::PUBLIC);
  auto& second_data_replicated = second_store.create<size_t, size_t>(
    "data_replicated", kv::SecurityDomain::PUBLIC);
  auto& data_derived =
    store.create<size_t, size_t>("data_derived", kv::SecurityDomain::PUBLIC);
  auto& second_data_derived = second_store.create<size_t, size_t>(
    "data_derived", kv::SecurityDomain::PUBLIC);
  auto& data_replicated_private =
    store.create<size_t, size_t>("data_replicated_private");
  auto& second_data_replicated_private =
    second_store.create<size_t, size_t>("data_replicated_private");
  auto& data_derived_private =
    store.create<size_t, size_t>("data_derived_private");
  auto& second_data_derived_private =
    second_store.create<size_t, size_t>("data_derived_private");

  {
    Store::Tx tx(store.next_version());

    auto [data_view_r, data_view_r_p, data_view_d, data_view_d_p] = tx.get_view(
      data_replicated,
      data_replicated_private,
      data_derived,
      data_derived_private);
    data_view_r->put(44, 44);
    data_view_r_p->put(45, 45);
    data_view_d->put(46, 46);
    data_view_d_p->put(47, 47);

    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);
    REQUIRE(store.deserialise(data) == kv::DeserialiseSuccess::PASS);

    INFO("check that second store derived data is not populated");
    {
      REQUIRE(second_store.deserialise(data) == kv::DeserialiseSuccess::PASS);
      Store::Tx tx;
      auto [data_view_r, data_view_r_p, data_view_d, data_view_d_p] =
        tx.get_view(
          second_data_replicated,
          second_data_replicated_private,
          second_data_derived,
          second_data_derived_private);
      auto dvr = data_view_r->get(44);
      REQUIRE(dvr.has_value());
      REQUIRE(dvr.value() == 44);

      auto dvrp = data_view_r_p->get(45);
      REQUIRE(dvrp.has_value());
      REQUIRE(dvrp.value() == 45);

      auto dvd = data_view_d->get(46);
      REQUIRE(!dvd.has_value());
      auto dvdp = data_view_d_p->get(47);
      REQUIRE(!dvdp.has_value());
    }
  }
}

struct NonSerialisable
{};

namespace msgpack
{
  MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS)
  {
    namespace adaptor
    {
      // msgpack conversion for uint256_t
      template <>
      struct convert<NonSerialisable>
      {
        msgpack::object const& operator()(
          msgpack::object const& o, NonSerialisable& ns) const
        {
          throw std::runtime_error("Deserialise failure");
        }
      };

      template <>
      struct pack<NonSerialisable>
      {
        template <typename Stream>
        packer<Stream>& operator()(
          msgpack::packer<Stream>& o, NonSerialisable const& ns) const
        {
          throw std::runtime_error("Serialise failure");
        }
      };
    }
  }
}

TEST_CASE("Exceptional serdes" * doctest::test_suite("serialisation"))
{
  auto encryptor = std::make_shared<ccf::NullTxEncryptor>();
  auto consensus = std::make_shared<kv::StubConsensus>();

  Store store(consensus);
  store.set_encryptor(encryptor);

  auto& good_map = store.create<size_t, size_t>("good_map");
  auto& bad_map = store.create<size_t, NonSerialisable>("bad_map");

  {
    Store::Tx tx;

    auto good_view = tx.get_view(good_map);
    good_view->put(1, 2);

    auto bad_view = tx.get_view(bad_map);
    bad_view->put(0, {});

    REQUIRE_THROWS_AS(tx.commit(), kv::KvSerialiserException);
  }
}
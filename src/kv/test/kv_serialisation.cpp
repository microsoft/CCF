// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "kv/encryptor.h"
#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "kv/tx.h"

#include <doctest/doctest.h>
#include <msgpack/msgpack.hpp>
#include <string>
#include <vector>

struct MapTypes
{
  using StringString = kv::Map<std::string, std::string>;
  using NumNum = kv::Map<size_t, size_t>;
  using NumString = kv::Map<size_t, std::string>;
  using StringNum = kv::Map<std::string, size_t>;
};

TEST_CASE(
  "Serialise/deserialise public map only" *
  doctest::test_suite("serialisation"))
{
  // No need for an encryptor here as all maps are public. Both serialisation
  // and deserialisation should succeed.
  auto consensus = std::make_shared<kv::StubConsensus>();

  kv::Store kv_store(consensus);

  auto& pub_map = kv_store.create<MapTypes::StringString>(
    "pub_map", kv::SecurityDomain::PUBLIC);

  kv::Store kv_store_target;
  kv_store_target.clone_schema(kv_store);
  auto* target_map = kv_store.get<MapTypes::StringString>("pub_map");
  REQUIRE(target_map != nullptr);

  INFO("Commit to public map in source store");
  {
    kv::Tx tx;
    auto view0 = tx.get_view(pub_map);
    view0->put("pubk1", "pubv1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Deserialise transaction in target store");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(!latest_data.value().empty());
    REQUIRE(
      kv_store_target.deserialise(latest_data.value()) ==
      kv::DeserialiseSuccess::PASS);

    kv::Tx tx_target;
    auto view_target = tx_target.get_view(*target_map);
    REQUIRE(view_target->get("pubk1") == "pubv1");
  }
}

TEST_CASE(
  "Serialise/deserialise private map only" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store kv_store(consensus);
  auto& priv_map = kv_store.create<MapTypes::StringString>("priv_map");

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);
  kv_store_target.clone_schema(kv_store);
  auto* target_map = kv_store.get<MapTypes::StringString>("priv_map");
  REQUIRE(target_map != nullptr);

  SUBCASE(
    "Commit a private transaction without an encryptor throws an exception")
  {
    kv::Tx tx;
    auto view0 = tx.get_view(priv_map);
    view0->put("privk1", "privv1");
    REQUIRE_THROWS_AS(tx.commit(), kv::KvSerialiserException);
  }

  SUBCASE("Commit private transaction with encryptor")
  {
    kv_store.set_encryptor(encryptor);
    INFO("Commit to private map in source store");
    {
      kv::Tx tx;
      auto view0 = tx.get_view(priv_map);
      view0->put("privk1", "privv1");
      REQUIRE(tx.commit() == kv::CommitSuccess::OK);
    }

    INFO("Deserialise transaction in target store");
    {
      const auto latest_data = consensus->get_latest_data();
      REQUIRE(latest_data.has_value());
      REQUIRE(
        kv_store_target.deserialise(latest_data.value()) ==
        kv::DeserialiseSuccess::PASS);

      kv::Tx tx_target;
      auto view_target = tx_target.get_view(*target_map);
      REQUIRE(view_target->get("privk1") == "privv1");
    }
  }
}

TEST_CASE(
  "Serialise/deserialise private map and public maps" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store kv_store(consensus);
  kv_store.set_encryptor(encryptor);
  auto& priv_map = kv_store.create<MapTypes::StringString>("priv_map");
  auto& pub_map = kv_store.create<MapTypes::StringString>(
    "pub_map", kv::SecurityDomain::PUBLIC);

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);
  kv_store_target.clone_schema(kv_store);
  auto* target_priv_map = kv_store.get<MapTypes::StringString>("priv_map");
  auto* target_pub_map = kv_store.get<MapTypes::StringString>("pub_map");
  REQUIRE(target_priv_map != nullptr);
  REQUIRE(target_pub_map != nullptr);

  INFO("Commit to public and private map in source store");
  {
    kv::Tx tx;
    auto [view_priv, view_pub] = tx.get_view(priv_map, pub_map);

    view_priv->put("privk1", "privv1");
    view_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit() == kv::CommitSuccess::OK);
  }

  INFO("Deserialise transaction in target store");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialise(latest_data.value()) !=
      kv::DeserialiseSuccess::FAILED);

    kv::Tx tx;
    auto [view_priv, view_pub] = tx.get_view(*target_priv_map, *target_pub_map);

    REQUIRE(view_priv->get("privk1") == "privv1");
    REQUIRE(view_pub->get("pubk1") == "pubv1");
  }
}

TEST_CASE(
  "Serialise/deserialise removed keys" * doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store kv_store(consensus);
  kv_store.set_encryptor(encryptor);
  auto& priv_map = kv_store.create<MapTypes::StringString>("priv_map");

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);
  kv_store_target.clone_schema(kv_store);
  auto* target_priv_map = kv_store.get<MapTypes::StringString>("priv_map");
  REQUIRE(target_priv_map != nullptr);

  INFO("Commit a new key in source store and deserialise in target store");
  {
    kv::Tx tx;
    auto view_priv = tx.get_view(priv_map);
    view_priv->put("privk1", "privv1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialise(latest_data.value()) !=
      kv::DeserialiseSuccess::FAILED);

    kv::Tx tx_target;
    auto view_priv_target = tx_target.get_view(*target_priv_map);
    REQUIRE(view_priv_target->get("privk1") == "privv1");
  }

  INFO("Commit key removal in source store and deserialise in target store");
  {
    kv::Tx tx;
    auto view_priv = tx.get_view(priv_map);
    view_priv->remove("privk1");
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    // Make sure it has been marked as deleted in source store
    kv::Tx tx2;
    auto view_priv2 = tx2.get_view(priv_map);
    REQUIRE(view_priv2->get("privk1").has_value() == false);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialise(latest_data.value()) !=
      kv::DeserialiseSuccess::FAILED);

    kv::Tx tx_target;
    auto view_priv_target = tx_target.get_view(*target_priv_map);
    REQUIRE(view_priv_target->get("privk1").has_value() == false);
  }
}

// SNIPPET_START: CustomClass definition
struct CustomClass
{
  std::string s;
  size_t n;

  // This macro allows the default msgpack serialiser to be used
  MSGPACK_DEFINE(s, n);
};
// SNIPPET_END: CustomClass definition

// SNIPPET_START: CustomSerialiser definition
struct CustomSerialiser
{
  /**
   * Format:
   * [ 8 bytes=n | 8 bytes=size_of_s | size_of_s bytes=s... ]
   */

  static constexpr auto size_of_n = 8;
  static constexpr auto size_of_size_of_s = 8;
  static kv::serialisers::SerialisedEntry to_serialised(const CustomClass& cc)
  {
    const auto s_size = cc.s.size();
    const auto total_size = size_of_n + size_of_size_of_s + s_size;
    kv::serialisers::SerialisedEntry serialised(total_size);
    uint8_t* data = serialised.data();
    memcpy(data, (const uint8_t*)&cc.n, size_of_n);
    data += size_of_n;
    memcpy(data, (const uint8_t*)&s_size, size_of_size_of_s);
    data += size_of_size_of_s;
    memcpy(data, (const uint8_t*)cc.s.data(), s_size);
    return serialised;
  }

  static CustomClass from_serialised(
    const kv::serialisers::SerialisedEntry& ser)
  {
    CustomClass cc;
    const uint8_t* data = ser.data();
    cc.n = *(const uint64_t*)data;
    data += size_of_n;
    const auto s_size = *(const uint64_t*)data;
    data += size_of_size_of_s;
    cc.s.resize(s_size);
    std::memcpy(cc.s.data(), data, s_size);
    return cc;
  }
};
// SNIPPET_END: CustomSerialiser definition

struct CustomJsonSerialiser
{
  using Bytes = kv::serialisers::SerialisedEntry;

  static Bytes to_serialised(const CustomClass& c)
  {
    nlohmann::json j = nlohmann::json::object();
    j["s"] = c.s;
    j["n"] = c.n;
    const auto s = j.dump();
    return Bytes(s.begin(), s.end());
  }

  static CustomClass from_serialised(const Bytes& b)
  {
    const auto j = nlohmann::json::parse(b);
    CustomClass c;
    c.s = j["s"];
    c.n = j["n"];
    return c;
  }
};

struct KPrefix
{
  static constexpr auto prefix = "This is a key:";
};

struct VPrefix
{
  static constexpr auto prefix = "Here follows a value:";
};

template <typename T>
struct CustomVerboseDumbSerialiser
{
  using Bytes = kv::serialisers::SerialisedEntry;

  static Bytes to_serialised(const CustomClass& c)
  {
    const auto verbose = fmt::format("{}\ns={}\nn={}", T::prefix, c.s, c.n);
    return Bytes(verbose.begin(), verbose.end());
  }

  static CustomClass from_serialised(const Bytes& b)
  {
    std::string s(b.begin(), b.end());
    const auto prefix_start = s.find(T::prefix);
    if (prefix_start != 0)
    {
      throw std::logic_error("Missing expected prefix");
    }

    CustomClass c;
    const auto first_linebreak = s.find('\n');
    const auto last_linebreak = s.rfind('\n');
    const auto seg_a = s.substr(0, first_linebreak);
    const auto seg_b =
      s.substr(first_linebreak + 1, last_linebreak - first_linebreak - 1);
    const auto seg_c = s.substr(last_linebreak + 1);

    c.s = seg_b.substr(strlen("s="));
    const auto n_str = seg_c.substr(strlen("n="));
    c.n = strtoul(n_str.c_str(), nullptr, 10);
    return c;
  }
};

using DefaultSerialisedMap = kv::Map<CustomClass, CustomClass>;

// SNIPPET_START: CustomSerialisedMap definition
using CustomSerialisedMap =
  kv::TypedMap<CustomClass, CustomClass, CustomSerialiser, CustomSerialiser>;
// SNIPPET_END: CustomSerialisedMap definition

using CustomJsonMap = kv::TypedMap<
  CustomClass,
  CustomClass,
  CustomJsonSerialiser,
  CustomJsonSerialiser>;
using VerboseSerialisedMap = kv::TypedMap<
  CustomClass,
  CustomClass,
  CustomVerboseDumbSerialiser<KPrefix>,
  CustomVerboseDumbSerialiser<VPrefix>>;

TEST_CASE_TEMPLATE(
  "Custom type serialisation test" * doctest::test_suite("serialisation"),
  MapType,
  DefaultSerialisedMap,
  CustomSerialisedMap,
  CustomJsonMap,
  VerboseSerialisedMap)
{
  kv::Store kv_store;

  auto& map = kv_store.create<MapType>("map", kv::SecurityDomain::PUBLIC);

  CustomClass k1{"hello", 42};
  CustomClass v1{"world", 43};

  CustomClass k2{"saluton", 100};
  CustomClass v2{"mondo", 1024};

  INFO("Serialise/Deserialise 2 kv stores");
  {
    kv::Store kv_store2;
    auto& map2 = kv_store2.create<MapType>("map", kv::SecurityDomain::PUBLIC);

    kv::Tx tx(kv_store.next_version());
    auto view = tx.get_view(map);
    view->put(k1, v1);
    view->put(k2, v2);

    auto [success, reqid, data] = tx.commit_reserved();
    REQUIRE(success == kv::CommitSuccess::OK);
    kv_store.compact(kv_store.current_version());

    REQUIRE(kv_store2.deserialise(data) == kv::DeserialiseSuccess::PASS);
    kv::Tx tx2;
    auto view2 = tx2.get_view(map2);

    // operator== does not need to be defined for custom types. In this case it
    // is not, and we check each member manually
    auto va = view2->get(k1);
    REQUIRE(va.has_value());
    REQUIRE(va->s == v1.s);
    REQUIRE(va->n == v1.n);

    auto vb = view2->get(k2);
    REQUIRE(vb.has_value());
    REQUIRE(vb->s == v2.s);
    REQUIRE(vb->n == v2.n);
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
    std::list<kv::TxEncryptor::KeyInfo> keys;
    std::vector<uint8_t> raw_key(crypto::GCM_SIZE_KEY);
    for (size_t i = 0; i < raw_key.size(); ++i)
    {
      raw_key[i] = i;
    }
    keys.push_back({kv::Version(0), raw_key});
    auto encryptor = std::make_shared<kv::TxEncryptor>(keys);
    encryptor->set_iv_id(1);

    kv::Store kv_store(consensus);
    kv::Store kv_store_target;
    kv_store.set_encryptor(encryptor);
    kv_store_target.set_encryptor(encryptor);

    auto& public_map = kv_store.create<MapTypes::StringString>(
      "public_map", kv::SecurityDomain::PUBLIC);
    auto& private_map = kv_store.create<MapTypes::StringString>("private_map");

    kv_store_target.clone_schema(kv_store);

    kv::Tx tx;
    auto [public_view, private_view] = tx.get_view(public_map, private_map);
    std::string pub_value = "pubv1";
    public_view->put("pubk1", pub_value);
    private_view->put("privk1", "privv1");
    auto rc = tx.commit();

    // Tamper with serialised public data
    auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    std::vector<uint8_t> value_to_corrupt(pub_value.begin(), pub_value.end());
    REQUIRE(corrupt_serialised_tx(latest_data.value(), value_to_corrupt));

    REQUIRE(
      kv_store_target.deserialise(latest_data.value()) ==
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
    using Table = kv::Map<std::vector<int>, std::string>;
    kv::Store s0(consensus), s1;
    auto& t = s0.create<Table>("t", kv::SecurityDomain::PUBLIC);
    s1.create<Table>("t");

    kv::Tx tx;
    tx.get_view(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.deserialise(latest_data.value()) != kv::DeserialiseSuccess::FAILED);
  }

  SUBCASE("nlohmann")
  {
    auto consensus = std::make_shared<kv::StubConsensus>();
    using Table = kv::Map<nlohmann::json, nlohmann::json>;
    kv::Store s0(consensus), s1;
    auto& t = s0.create<Table>("t", kv::SecurityDomain::PUBLIC);
    s1.create<Table>("t");

    kv::Tx tx;
    tx.get_view(t)->put(k0, v0);
    tx.get_view(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitSuccess::OK);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.deserialise(latest_data.value()) != kv::DeserialiseSuccess::FAILED);
  }
}

TEST_CASE(
  "Replicated and derived table serialisation" *
  doctest::test_suite("serialisation"))
{
  using T = MapTypes::NumNum;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  std::unordered_set<std::string> replicated_tables = {
    "data_replicated", "data_replicated_private"};

  kv::Store store(kv::ReplicateType::SOME, replicated_tables);
  store.set_encryptor(encryptor);
  auto& data_replicated =
    store.create<T>("data_replicated", kv::SecurityDomain::PUBLIC);
  auto& data_derived =
    store.create<T>("data_derived", kv::SecurityDomain::PUBLIC);
  auto& data_replicated_private = store.create<T>("data_replicated_private");
  auto& data_derived_private = store.create<T>("data_derived_private");

  kv::Store kv_store_target(kv::ReplicateType::SOME, replicated_tables);
  kv_store_target.set_encryptor(encryptor);
  kv_store_target.clone_schema(store);
  auto* second_data_replicated =
    kv_store_target.get<T>(data_replicated.get_name());
  auto* second_data_derived = kv_store_target.get<T>(data_derived.get_name());
  auto* second_data_replicated_private =
    kv_store_target.get<T>(data_replicated_private.get_name());
  auto* second_data_derived_private =
    kv_store_target.get<T>(data_derived_private.get_name());
  REQUIRE(second_data_replicated != nullptr);
  REQUIRE(second_data_derived != nullptr);
  REQUIRE(second_data_replicated_private != nullptr);
  REQUIRE(second_data_derived_private != nullptr);

  {
    kv::Tx tx(store.next_version());

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
      REQUIRE(
        kv_store_target.deserialise(data) == kv::DeserialiseSuccess::PASS);
      kv::Tx tx;
      auto [data_view_r, data_view_r_p, data_view_d, data_view_d_p] =
        tx.get_view(
          *second_data_replicated,
          *second_data_replicated_private,
          *second_data_derived,
          *second_data_derived_private);
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

struct NonSerialiser
{
  using Bytes = kv::serialisers::SerialisedEntry;

  static Bytes to_serialised(const NonSerialisable& ns)
  {
    throw std::runtime_error("Serialise failure");
  }

  static NonSerialisable from_serialised(const Bytes& b)
  {
    throw std::runtime_error("Deserialise failure");
  }
};

TEST_CASE("Exceptional serdes" * doctest::test_suite("serialisation"))
{
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  auto consensus = std::make_shared<kv::StubConsensus>();

  kv::Store store(consensus);
  store.set_encryptor(encryptor);

  auto& bad_map_k = store.create<kv::TypedMap<
    NonSerialisable,
    size_t,
    NonSerialiser,
    kv::serialisers::MsgPackSerialiser<size_t>>>("bad_map_k");
  auto& bad_map_v = store.create<kv::TypedMap<
    size_t,
    NonSerialisable,
    kv::serialisers::MsgPackSerialiser<size_t>,
    NonSerialiser>>("bad_map_v");

  {
    kv::Tx tx;
    auto bad_view = tx.get_view(bad_map_k);
    REQUIRE_THROWS(bad_view->put({}, 0));
  }

  {
    kv::Tx tx;
    auto bad_view = tx.get_view(bad_map_v);
    REQUIRE_THROWS(bad_view->put(0, {}));
  }
}
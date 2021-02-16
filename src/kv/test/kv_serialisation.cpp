// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/logger.h"
#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "kv/tx.h"

#include <doctest/doctest.h>
#undef FAIL
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

  kv::Store kv_store_target;

  MapTypes::StringString map("public:pub_map");

  const auto k1 = "pubk1";
  const auto k2 = "pubk2";
  const auto k3 = "pubk3";
  const auto k4 = "never_written";

  const auto v1 = "pubv1";
  const auto v2 = "pubv2";

  {
    INFO("Commit to public map in source store");
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw(map);
    handle0->put(k1, v1);
    handle0->put(k2, v1);
    handle0->put(k3, v1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  const auto first_version = kv_store.current_version();
  const auto first_tx_serialised = consensus->get_latest_data();
  REQUIRE(first_tx_serialised.has_value());
  REQUIRE(!first_tx_serialised.value().empty());

  {
    INFO("Modify source store in second transaction");
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw(map);
    // no change to k1, write to k2, remove k3
    handle0->put(k2, v2);
    handle0->remove(k3);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  const auto second_version = kv_store.current_version();
  const auto second_tx_serialised = consensus->get_latest_data();
  REQUIRE(second_tx_serialised.has_value());
  REQUIRE(!second_tx_serialised.value().empty());

  {
    INFO("Deserialise first transaction in target store");
    REQUIRE(
      kv_store_target.apply(first_tx_serialised.value(), ConsensusType::CFT)
        ->execute() == kv::ApplyResult::PASS);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.ro(map);

    REQUIRE(handle_target->has(k1));
    REQUIRE(handle_target->get(k1) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k1) == first_version);

    REQUIRE(handle_target->has(k2));
    REQUIRE(handle_target->get(k2) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k2) == first_version);

    REQUIRE(handle_target->has(k3));
    REQUIRE(handle_target->get(k3) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k3) == first_version);

    REQUIRE(!handle_target->has(k4));
    REQUIRE(!handle_target->get_version_of_previous_write(k4).has_value());
  }

  {
    INFO("Deserialise second transaction in target store");
    REQUIRE(
      kv_store_target.apply(second_tx_serialised.value(), ConsensusType::CFT)
        ->execute() == kv::ApplyResult::PASS);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.ro(map);

    REQUIRE(handle_target->has(k1));
    REQUIRE(handle_target->get(k1) == v1);
    REQUIRE(handle_target->get_version_of_previous_write(k1) == first_version);

    REQUIRE(handle_target->has(k2));
    REQUIRE(handle_target->get(k2) == v2);
    REQUIRE(handle_target->get_version_of_previous_write(k2) == second_version);

    REQUIRE(!handle_target->has(k3));
    REQUIRE(!handle_target->get_version_of_previous_write(k3).has_value());

    REQUIRE(!handle_target->has(k4));
    REQUIRE(!handle_target->get_version_of_previous_write(k4).has_value());
  }
}

TEST_CASE(
  "Serialise/deserialise private map only" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store kv_store(consensus);

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  SUBCASE(
    "Commit a private transaction without an encryptor throws an exception")
  {
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw<MapTypes::StringString>("priv_map");
    handle0->put("privk1", "privv1");
    REQUIRE_THROWS_AS(tx.commit(), kv::KvSerialiserException);
  }

  SUBCASE("Commit private transaction with encryptor")
  {
    kv_store.set_encryptor(encryptor);
    INFO("Commit to private map in source store");
    {
      auto tx = kv_store.create_tx();
      auto handle0 = tx.rw<MapTypes::StringString>("priv_map");
      handle0->put("privk1", "privv1");
      REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
    }

    INFO("Deserialise transaction in target store");
    {
      const auto latest_data = consensus->get_latest_data();
      REQUIRE(latest_data.has_value());
      REQUIRE(
        kv_store_target.apply(latest_data.value(), ConsensusType::CFT)
          ->execute() == kv::ApplyResult::PASS);

      auto tx_target = kv_store_target.create_tx();
      auto handle_target = tx_target.rw<MapTypes::StringString>("priv_map");
      REQUIRE(handle_target->get("privk1") == "privv1");
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

  constexpr auto priv_map = "priv_map";
  constexpr auto pub_map = "public:pub_map";

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  INFO("Commit to public and private map in source store");
  {
    auto tx = kv_store.create_tx();
    auto handle_priv = tx.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx.rw<MapTypes::StringString>(pub_map);

    handle_priv->put("privk1", "privv1");
    handle_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
  }

  INFO("Deserialise transaction in target store");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.apply(latest_data.value(), ConsensusType::CFT)
        ->execute() != kv::ApplyResult::FAIL);

    auto tx_target = kv_store_target.create_tx();
    auto handle_priv = tx_target.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx_target.rw<MapTypes::StringString>(pub_map);

    REQUIRE(handle_priv->get("privk1") == "privv1");
    REQUIRE(handle_pub->get("pubk1") == "pubv1");
  }
}

TEST_CASE(
  "Serialise/deserialise removed keys" * doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<kv::StubConsensus>();
  auto encryptor = std::make_shared<kv::NullTxEncryptor>();

  kv::Store kv_store(consensus);
  kv_store.set_encryptor(encryptor);

  kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  INFO("Commit new keys in source store and deserialise in target store");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("map");
    auto handle2 = tx.rw<MapTypes::StringString>("map2");
    handle->put("key1", "value1");
    handle2->put("key2", "value2");
    handle2->put("key3", "value3");
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.apply(latest_data.value(), ConsensusType::CFT)
        ->execute() != kv::ApplyResult::FAIL);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.rw<MapTypes::StringString>("map");
    auto handle_target2 = tx_target.rw<MapTypes::StringString>("map2");
    REQUIRE(handle_target->get("key1") == "value1");
    REQUIRE(handle_target2->get("key2") == "value2");
    REQUIRE(handle_target2->get("key3") == "value3");
  }

  INFO("Commit keys removal in source store and deserialise in target store");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("map");
    auto handle_ = tx.rw<MapTypes::StringString>("map2");

    // Key only exists in state
    REQUIRE(handle->remove("key1"));

    // Key exists in write set as well as state
    handle_->put("key2", "value2");
    REQUIRE(handle_->remove("key2"));

    // Key doesn't exist in either write set or state
    REQUIRE_FALSE(handle->remove("unknown_key"));

    // Key only exists in write set
    handle_->put("uncommitted_key", "uncommitted_value");
    REQUIRE(handle_->remove("uncommitted_key"));

    // Key is removed then added again
    REQUIRE(handle_->remove("key3"));
    handle_->put("key3", "value3");

    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    // Make sure keys have been marked as deleted in source store
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw<MapTypes::StringString>("map");
    auto handle_2 = tx2.rw<MapTypes::StringString>("map2");
    REQUIRE_FALSE(handle2->get("key1").has_value());
    REQUIRE_FALSE(handle_2->get("key2").has_value());
    REQUIRE_FALSE(handle2->get("unknown_key").has_value());
    REQUIRE_FALSE(handle_2->get("uncommitted_key").has_value());

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.apply(latest_data.value(), ConsensusType::CFT)
        ->execute() != kv::ApplyResult::FAIL);

    auto tx_target = kv_store_target.create_tx();
    auto handle_target = tx_target.rw<MapTypes::StringString>("map");
    auto handle_target_2 = tx_target.rw<MapTypes::StringString>("map2");
    REQUIRE_FALSE(handle_target->get("key1").has_value());
    REQUIRE_FALSE(handle_target_2->get("key2").has_value());
    REQUIRE_FALSE(handle_target->get("unknown_key").has_value());
    REQUIRE_FALSE(handle_target_2->get("uncommitted_key").has_value());
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

// These macros allow the default nlohmann JSON serialiser to be used
DECLARE_JSON_TYPE(CustomClass);
DECLARE_JSON_REQUIRED_FIELDS(CustomClass, s, n);

// Not really intended to be extended, but lets us use the BlitSerialiser for
// this specific type
namespace kv::serialisers
{
  template <>
  struct BlitSerialiser<CustomClass>
  {
    static SerialisedEntry to_serialised(const CustomClass& cc)
    {
      // Don't encode size, entire remainder of buffer is string
      const auto s_size = cc.s.size();
      const auto total_size = sizeof(cc.n) + s_size;
      SerialisedEntry s(total_size);

      uint8_t* data = s.data();
      size_t remaining = s.size();

      memcpy(data, (void*)&cc.n, sizeof(cc.n));
      data += sizeof(cc.n);
      remaining -= sizeof(cc.n);

      memcpy(data, (void*)cc.s.c_str(), remaining);

      return s;
    }

    static CustomClass from_serialised(const SerialisedEntry& s)
    {
      CustomClass cc;
      const uint8_t* data = s.data();
      size_t remaining = s.size();

      cc.n = *(decltype(cc.n)*)data;
      data += sizeof(cc.n);
      remaining -= sizeof(cc.n);

      cc.s.assign(data, data + remaining);

      return cc;
    }
  };
}

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
    const auto j = nlohmann::json::parse(b.begin(), b.end());
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
using JsonSerialisedMap = kv::JsonSerialisedMap<CustomClass, CustomClass>;
using RawCopySerialisedMap = kv::RawCopySerialisedMap<CustomClass, CustomClass>;
using MixSerialisedMapA = kv::TypedMap<
  CustomClass,
  CustomClass,
  kv::serialisers::MsgPackSerialiser<CustomClass>,
  kv::serialisers::JsonSerialiser<CustomClass>>;
using MixSerialisedMapB = kv::TypedMap<
  CustomClass,
  CustomClass,
  kv::serialisers::JsonSerialiser<CustomClass>,
  kv::serialisers::BlitSerialiser<CustomClass>>;
using MixSerialisedMapC = kv::TypedMap<
  CustomClass,
  CustomClass,
  kv::serialisers::BlitSerialiser<CustomClass>,
  kv::serialisers::MsgPackSerialiser<CustomClass>>;

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
  JsonSerialisedMap,
  RawCopySerialisedMap,
  MixSerialisedMapA,
  MixSerialisedMapB,
  MixSerialisedMapC,
  CustomSerialisedMap,
  CustomJsonMap,
  VerboseSerialisedMap)
{
  kv::Store kv_store;

  MapType map("public:map");

  CustomClass k1{"hello", 42};
  CustomClass v1{"world", 43};

  CustomClass k2{"saluton", 100};
  CustomClass v2{"mondo", 1024};

  INFO("Serialise/Deserialise 2 kv stores");
  {
    kv::Store kv_store2;
    MapType map2("public:map");

    auto tx = kv_store.create_reserved_tx(kv_store.next_version());
    auto handle = tx.rw(map);
    handle->put(k1, v1);
    handle->put(k2, v2);

    auto [success, reqid, data, hooks] = tx.commit_reserved();
    REQUIRE(success == kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    REQUIRE(
      kv_store2.apply(data, ConsensusType::CFT)->execute() ==
      kv::ApplyResult::PASS);
    auto tx2 = kv_store2.create_tx();
    auto handle2 = tx2.rw(map2);

    // operator== does not need to be defined for custom types. In this case it
    // is not, and we check each member manually
    auto va = handle2->get(k1);
    REQUIRE(va.has_value());
    REQUIRE(va->s == v1.s);
    REQUIRE(va->n == v1.n);

    auto vb = handle2->get(k2);
    REQUIRE(vb.has_value());
    REQUIRE(vb->s == v2.s);
    REQUIRE(vb->n == v2.n);
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
    Table t("public:t");

    auto tx = s0.create_tx();
    tx.rw(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.apply(latest_data.value(), ConsensusType::CFT)->execute() !=
      kv::ApplyResult::FAIL);
  }

  SUBCASE("nlohmann")
  {
    auto consensus = std::make_shared<kv::StubConsensus>();
    using Table = kv::Map<nlohmann::json, nlohmann::json>;
    kv::Store s0(consensus), s1;
    Table t("public:t");

    auto tx = s0.create_tx();
    tx.rw(t)->put(k0, v0);
    tx.rw(t)->put(k1, v1);
    REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.apply(latest_data.value(), ConsensusType::CFT)->execute() !=
      kv::ApplyResult::FAIL);
  }
}

TEST_CASE(
  "Replicated and derived table serialisation" *
  doctest::test_suite("serialisation"))
{
  using T = MapTypes::NumNum;

  auto encryptor = std::make_shared<kv::NullTxEncryptor>();
  constexpr auto data_replicated = "public:data_replicated";
  constexpr auto data_derived = "data_replicated";
  constexpr auto data_replicated_private = "public:data_replicated_private";
  constexpr auto data_derived_private = "data_replicated_private";
  std::unordered_set<std::string> replicated_tables = {data_replicated,
                                                       data_replicated_private};

  kv::Store store(kv::ReplicateType::SOME, replicated_tables);
  store.set_encryptor(encryptor);

  kv::Store kv_store_target(kv::ReplicateType::SOME, replicated_tables);
  kv_store_target.set_encryptor(encryptor);

  {
    auto tx = store.create_reserved_tx(store.next_version());

    auto data_handle_r = tx.rw<T>(data_replicated);
    auto data_handle_r_p = tx.rw<T>(data_replicated_private);
    auto data_handle_d = tx.rw<T>(data_derived);
    auto data_handle_d_p = tx.rw<T>(data_derived_private);
    data_handle_r->put(44, 44);
    data_handle_r_p->put(45, 45);
    data_handle_d->put(46, 46);
    data_handle_d_p->put(47, 47);

    auto [success, reqid, data, hooks] = tx.commit_reserved();
    REQUIRE(success == kv::CommitResult::SUCCESS);
    REQUIRE(
      store.apply(data, ConsensusType::CFT)->execute() ==
      kv::ApplyResult::PASS);

    INFO("check that second store derived data is not populated");
    {
      REQUIRE(
        kv_store_target.apply(data, ConsensusType::CFT)->execute() ==
        kv::ApplyResult::PASS);
      auto tx = kv_store_target.create_tx();
      auto data_handle_r = tx.rw<T>(data_replicated);
      auto data_handle_r_p = tx.rw<T>(data_replicated_private);
      auto data_handle_d = tx.rw<T>(data_derived);
      auto data_handle_d_p = tx.rw<T>(data_derived_private);
      auto dvr = data_handle_r->get(44);
      REQUIRE(dvr.has_value());
      REQUIRE(dvr.value() == 44);

      auto dvrp = data_handle_r_p->get(45);
      REQUIRE(dvrp.has_value());
      REQUIRE(dvrp.value() == 45);

      auto dvd = data_handle_d->get(46);
      REQUIRE(!dvd.has_value());
      auto dvdp = data_handle_d_p->get(47);
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

  kv::TypedMap<
    NonSerialisable,
    size_t,
    NonSerialiser,
    kv::serialisers::MsgPackSerialiser<size_t>>
    bad_map_k("bad_map_k");
  kv::TypedMap<
    size_t,
    NonSerialisable,
    kv::serialisers::MsgPackSerialiser<size_t>,
    NonSerialiser>
    bad_map_v("bad_map_v");

  {
    auto tx = store.create_tx();
    auto bad_handle = tx.rw(bad_map_k);
    REQUIRE_THROWS(bad_handle->put({}, 0));
  }

  {
    auto tx = store.create_tx();
    auto bad_handle = tx.rw(bad_map_v);
    REQUIRE_THROWS(bad_handle->put(0, {}));
  }
}
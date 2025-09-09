// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ds/internal_logger.h"
#include "kv/kv_serialiser.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"

#include <doctest/doctest.h>
#undef FAIL
#include <string>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using NumString = ccf::kv::Map<size_t, std::string>;
  using StringNum = ccf::kv::Map<std::string, size_t>;
};

TEST_CASE(
  "Serialise/deserialise public map only" *
  doctest::test_suite("serialisation"))
{
  // No need for an encryptor here as all maps are public. Both serialisation
  // and deserialisation should succeed.

  ccf::kv::Store kv_store;

  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  kv_store.set_consensus(consensus);
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  ccf::kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

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
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
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
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto second_version = kv_store.current_version();
  const auto second_tx_serialised = consensus->get_latest_data();
  REQUIRE(second_tx_serialised.has_value());
  REQUIRE(!second_tx_serialised.value().empty());

  {
    INFO("Deserialise first transaction in target store");
    REQUIRE(
      kv_store_target.deserialize(first_tx_serialised.value())->apply() ==
      ccf::kv::ApplyResult::PASS);

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
      kv_store_target.deserialize(second_tx_serialised.value())->apply() ==
      ccf::kv::ApplyResult::PASS);

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
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::kv::Store kv_store;
  kv_store.set_consensus(consensus);

  ccf::kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  SUBCASE(
    "Commit a private transaction without an encryptor throws an exception")
  {
    auto tx = kv_store.create_tx();
    auto handle0 = tx.rw<MapTypes::StringString>("priv_map");
    handle0->put("privk1", "privv1");
    REQUIRE_THROWS_AS(tx.commit(), ccf::kv::KvSerialiserException);
  }

  SUBCASE("Commit private transaction with encryptor")
  {
    kv_store.set_encryptor(encryptor);
    INFO("Commit to private map in source store");
    {
      auto tx = kv_store.create_tx();
      auto handle0 = tx.rw<MapTypes::StringString>("priv_map");
      handle0->put("privk1", "privv1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Deserialise transaction in target store");
    {
      const auto latest_data = consensus->get_latest_data();
      REQUIRE(latest_data.has_value());
      REQUIRE(
        kv_store_target.deserialize(latest_data.value())->apply() ==
        ccf::kv::ApplyResult::PASS);

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
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::kv::Store kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  constexpr auto priv_map = "priv_map";
  constexpr auto pub_map = "public:pub_map";

  ccf::kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  INFO("Commit to public and private map in source store");
  {
    auto tx = kv_store.create_tx();
    auto handle_priv = tx.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx.rw<MapTypes::StringString>(pub_map);

    handle_priv->put("privk1", "privv1");
    handle_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Deserialise transaction in target store");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);

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
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::kv::Store kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  ccf::kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  INFO("Commit new keys in source store and deserialise in target store");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw<MapTypes::StringString>("map");
    auto handle2 = tx.rw<MapTypes::StringString>("map2");
    handle->put("key1", "value1");
    handle2->put("key2", "value2");
    handle2->put("key3", "value3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      kv_store_target.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);

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
    handle->remove("key1");

    // Key exists in write set as well as state
    handle_->put("key2", "value2");
    handle_->remove("key2");

    // Key doesn't exist in either write set or state
    handle->remove("unknown_key");

    // Key only exists in write set
    handle_->put("uncommitted_key", "uncommitted_value");
    handle_->remove("uncommitted_key");

    // Key is removed then added again
    handle_->remove("key3");
    handle_->put("key3", "value3");

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

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
      kv_store_target.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);

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
};

// These macros allow the default nlohmann JSON serialiser to be used
DECLARE_JSON_TYPE(CustomClass);
DECLARE_JSON_REQUIRED_FIELDS(CustomClass, s, n);
// SNIPPET_END: CustomClass definition

// Not really intended to be extended, but lets us use the BlitSerialiser for
// this specific type
namespace ccf::kv::serialisers
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
  static ccf::kv::serialisers::SerialisedEntry to_serialised(
    const CustomClass& cc)
  {
    const auto s_size = cc.s.size();
    const auto total_size = size_of_n + size_of_size_of_s + s_size;
    ccf::kv::serialisers::SerialisedEntry serialised(total_size);
    uint8_t* data = serialised.data();
    memcpy(data, (const uint8_t*)&cc.n, size_of_n);
    data += size_of_n;
    memcpy(data, (const uint8_t*)&s_size, size_of_size_of_s);
    data += size_of_size_of_s;
    memcpy(data, (const uint8_t*)cc.s.data(), s_size);
    return serialised;
  }

  static CustomClass from_serialised(
    const ccf::kv::serialisers::SerialisedEntry& ser)
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
  using Bytes = ccf::kv::serialisers::SerialisedEntry;

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
  using Bytes = ccf::kv::serialisers::SerialisedEntry;

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

using JsonSerialisedMap = ccf::kv::JsonSerialisedMap<CustomClass, CustomClass>;
using RawCopySerialisedMap =
  ccf::kv::RawCopySerialisedMap<CustomClass, CustomClass>;
using MixSerialisedMapB = ccf::kv::TypedMap<
  CustomClass,
  CustomClass,
  ccf::kv::serialisers::JsonSerialiser<CustomClass>,
  ccf::kv::serialisers::BlitSerialiser<CustomClass>>;

// SNIPPET_START: CustomSerialisedMap definition
using CustomSerialisedMap = ccf::kv::
  TypedMap<CustomClass, CustomClass, CustomSerialiser, CustomSerialiser>;
// SNIPPET_END: CustomSerialisedMap definition

using CustomJsonMap = ccf::kv::TypedMap<
  CustomClass,
  CustomClass,
  CustomJsonSerialiser,
  CustomJsonSerialiser>;
using VerboseSerialisedMap = ccf::kv::TypedMap<
  CustomClass,
  CustomClass,
  CustomVerboseDumbSerialiser<KPrefix>,
  CustomVerboseDumbSerialiser<VPrefix>>;

TEST_CASE_TEMPLATE(
  "Custom type serialisation test" * doctest::test_suite("serialisation"),
  MapType,
  JsonSerialisedMap,
  RawCopySerialisedMap,
  MixSerialisedMapB,
  CustomSerialisedMap,
  CustomJsonMap,
  VerboseSerialisedMap)
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  MapType map("public:map");

  CustomClass k1{"hello", 42};
  CustomClass v1{"world", 43};

  CustomClass k2{"saluton", 100};
  CustomClass v2{"mondo", 1024};

  INFO("Serialise/Deserialise 2 kv stores");
  {
    ccf::kv::Store kv_store2;
    kv_store2.set_encryptor(encryptor);

    MapType map2("public:map");

    auto tx = kv_store.create_reserved_tx(kv_store.next_txid());
    auto handle = tx.rw(map);
    handle->put(k1, v1);
    handle->put(k2, v2);

    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    REQUIRE(kv_store2.deserialize(data)->apply() == ccf::kv::ApplyResult::PASS);
    auto tx2 = kv_store2.create_tx();
    auto handle2 = tx2.rw(map2);

    // operator== does not need to be defined for custom types. In this case
    // it is not, and we check each member manually
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
    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    using Table = ccf::kv::Map<std::vector<int>, std::string>;
    ccf::kv::Store s0, s1;
    s0.set_consensus(consensus);
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    s0.set_encryptor(encryptor);
    s1.set_encryptor(encryptor);

    Table t("public:t");

    auto tx = s0.create_tx();
    tx.rw(t)->put(k1, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);
  }

  SUBCASE("nlohmann")
  {
    auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
    using Table = ccf::kv::Map<nlohmann::json, nlohmann::json>;
    ccf::kv::Store s0, s1;
    s0.set_consensus(consensus);
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    s0.set_encryptor(encryptor);
    s1.set_encryptor(encryptor);

    Table t("public:t");

    auto tx = s0.create_tx();
    tx.rw(t)->put(k0, v0);
    tx.rw(t)->put(k1, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    REQUIRE(
      s1.deserialize(latest_data.value())->apply() !=
      ccf::kv::ApplyResult::FAIL);
  }
}

struct NonSerialisable
{};

struct NonSerialiser
{
  using Bytes = ccf::kv::serialisers::SerialisedEntry;

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
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();

  ccf::kv::Store store;
  store.set_consensus(consensus);
  store.set_encryptor(encryptor);

  ccf::kv::TypedMap<
    NonSerialisable,
    size_t,
    NonSerialiser,
    ccf::kv::serialisers::JsonSerialiser<size_t>>
    bad_map_k("bad_map_k");
  ccf::kv::TypedMap<
    size_t,
    NonSerialisable,
    ccf::kv::serialisers::JsonSerialiser<size_t>,
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

TEST_CASE(
  "Serialise/deserialise maps with claims" *
  doctest::test_suite("serialisation"))
{
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();

  ccf::kv::Store kv_store;
  kv_store.set_consensus(consensus);
  kv_store.set_encryptor(encryptor);

  constexpr auto priv_map = "priv_map";
  constexpr auto pub_map = "public:pub_map";

  ccf::kv::Store kv_store_target;
  kv_store_target.set_encryptor(encryptor);

  ccf::ClaimsDigest claims_digest;
  claims_digest.set(ccf::crypto::Sha256Hash("claim text"));

  INFO("Commit to source store, including claims");
  {
    auto tx = kv_store.create_tx();
    auto handle_priv = tx.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx.rw<MapTypes::StringString>(pub_map);

    handle_priv->put("privk1", "privv1");
    handle_pub->put("pubk1", "pubv1");

    REQUIRE(tx.commit(claims_digest) == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Deserialise transaction in target store and extract claims");
  {
    const auto latest_data = consensus->get_latest_data();
    REQUIRE(latest_data.has_value());
    auto wrapper = kv_store_target.deserialize(latest_data.value());
    REQUIRE(wrapper->apply() != ccf::kv::ApplyResult::FAIL);
    auto deserialised_claims = wrapper->consume_claims_digest();
    REQUIRE(claims_digest == deserialised_claims);

    auto tx_target = kv_store_target.create_tx();
    auto handle_priv = tx_target.rw<MapTypes::StringString>(priv_map);
    auto handle_pub = tx_target.rw<MapTypes::StringString>(pub_map);

    REQUIRE(handle_priv->get("privk1") == "privv1");
    REQUIRE(handle_pub->get("pubk1") == "pubv1");
  }
}
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/app_interface.h"
#include "ccf/crypto/openssl_init.h"
#include "ccf/ds/logger.h"
#include "ccf/kv/map.h"
#include "ccf/kv/set.h"
#include "ccf/kv/value.h"
#include "crypto/openssl/hash.h"
#include "kv/compacted_version_conflict.h"
#include "kv/kv_serialiser.h"
#include "kv/ledger_chunker.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "kv/test/stub_consensus.h"
#include "node/history.h"

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>
#undef FAIL
#include <random>
#include <set>
#include <string>
#include <vector>

struct MapTypes
{
  using StringString = ccf::kv::Map<std::string, std::string>;
  using NumNum = ccf::kv::Map<size_t, size_t>;
  using NumString = ccf::kv::Map<size_t, std::string>;
  using StringNum = ccf::kv::Map<std::string, size_t>;
  using UntypedMap = ccf::kv::untyped::Map;
};

TEST_CASE("Map name parsing")
{
  using SD = ccf::kv::SecurityDomain;
  using AC = ccf::kv::AccessCategory;

  auto parse = ccf::kv::parse_map_name;
  auto mp = std::make_pair<SD, AC>;

  REQUIRE(parse("foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:foo") == mp(SD::PUBLIC, AC::APPLICATION));
  REQUIRE(parse("public:ccf.gov.foo") == mp(SD::PUBLIC, AC::GOVERNANCE));
  REQUIRE(parse("ccf.internal.foo") == mp(SD::PRIVATE, AC::INTERNAL));
  REQUIRE(parse("public:ccf.internal.foo") == mp(SD::PUBLIC, AC::INTERNAL));

  REQUIRE_THROWS(parse("ccf.foo"));
  REQUIRE_THROWS(parse("public:ccf.foo"));

  // Typos may lead to unexpected behaviour!
  REQUIRE(parse("publik:ccf.gov.foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("PUBLIC:ccf.gov.foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:Ccf.gov.foo") == mp(SD::PUBLIC, AC::APPLICATION));

  REQUIRE(parse("ccf_foo") == mp(SD::PRIVATE, AC::APPLICATION));
  REQUIRE(parse("public:ccf_foo") == mp(SD::PUBLIC, AC::APPLICATION));
}

TEST_CASE("Reads/writes and deletions")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Start empty transaction");
  {
    auto tx = kv_store.create_tx();
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    REQUIRE_THROWS_AS(tx.commit(), std::logic_error);
  }

  INFO("Read own writes");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(!handle->has(k));
    auto v = handle->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(!handle->get_version_of_previous_write(k).has_value());
    handle->put(k, v1);
    REQUIRE(handle->has(k));
    auto va = handle->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(!handle->get_version_of_previous_write(k).has_value());
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto commit_v = kv_store.current_version();

  INFO("Read previous writes");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE(handle->has(k));
    auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);
    const auto ver = handle->get_version_of_previous_write(k);
    REQUIRE(ver.has_value());
    REQUIRE(ver.value() == commit_v);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Remove keys");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k, v1);

      REQUIRE(!handle->has(invalid_key));
      handle->remove(invalid_key);
      REQUIRE(!handle->get_version_of_previous_write(invalid_key).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).value() == commit_v);
      handle->remove(k);
      REQUIRE(handle->get_version_of_previous_write(k).has_value());
      REQUIRE(handle->get_version_of_previous_write(k).value() == commit_v);
      REQUIRE(!handle->has(k));
      auto va = handle->get(k);
      REQUIRE(!va.has_value());

      handle->put(k, v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);
      REQUIRE(handle2->has(k));
      handle2->remove(k);
    }
  }

  INFO("Remove key that was deleted from state");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k, v1);
      auto va = handle->get_globally_committed(k);
      REQUIRE(!va.has_value());
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx2 = kv_store.create_tx();
      auto handle2 = tx2.rw(map);
      REQUIRE(handle2->has(k));
      handle2->remove(k);
      REQUIRE(!handle2->has(k));
      REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx3 = kv_store.create_tx();
      auto handle3 = tx3.rw(map);
      REQUIRE(!handle3->has(k));
      auto vc = handle3->get(k);
      REQUIRE(!vc.has_value());
    }
  }
}

TEST_CASE("sets and values")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  {
    INFO("ccf::kv::Set");
    using Set = ccf::kv::Set<std::string>;
    Set set("public:set");
    constexpr auto k1 = "key1";
    constexpr auto k2 = "key2";

    {
      INFO("Read own writes");
      auto tx = kv_store.create_tx();
      auto set_handle = tx.rw(set);

      REQUIRE(!set_handle->contains(k1));
      REQUIRE(set_handle->size() == 0);

      set_handle->insert(k1);
      REQUIRE(set_handle->contains(k1));
      REQUIRE(set_handle->size() == 1);

      REQUIRE(!set_handle->contains(k2));
      set_handle->insert(k2);
      REQUIRE(set_handle->contains(k2));
      REQUIRE(set_handle->size() == 2);

      REQUIRE(!set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      set_handle->remove(k2);
      REQUIRE(!set_handle->contains(k2));
      REQUIRE(set_handle->size() == 1);

      REQUIRE(!set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read previous writes");
      auto tx = kv_store.create_tx();
      auto set_handle = tx.ro(set);
      REQUIRE(set_handle->contains(k1));
      REQUIRE(!set_handle->contains(k2));

      // NB: Previous transaction committed locally, but not yet globally
      REQUIRE(!set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      REQUIRE(set_handle->size() == 1);
      std::set<std::string> std_set;
      set_handle->foreach([&std_set](const std::string& entry) {
        std_set.insert(entry);
        return true;
      });
      REQUIRE(std_set.size() == 1);
      REQUIRE(std_set.find(k1) != std_set.end());
      REQUIRE(std_set.find(k2) == std_set.end());
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read committed writes");
      kv_store.compact(kv_store.current_version());

      auto tx = kv_store.create_tx();
      auto set_handle = tx.rw(set);

      REQUIRE(set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      // Local modifications do not affect globally_committed
      set_handle->remove(k1);
      set_handle->insert(k2);

      REQUIRE(set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      // This tx is deliberately dropped, not committed
    }

    {
      INFO("Remove keys");
      auto tx = kv_store.create_tx();
      auto set_handle = tx.rw(set);

      REQUIRE(set_handle->contains(k1));
      REQUIRE(set_handle->size() == 1);

      set_handle->remove(k2);
      REQUIRE(set_handle->contains(k1));
      REQUIRE(set_handle->size() == 1);

      set_handle->remove(k1);
      REQUIRE(!set_handle->contains(k1));
      REQUIRE(set_handle->size() == 0);

      // Not even locally committed, so globally_committed is unaffected
      REQUIRE(set_handle->contains_globally_committed(k1));
      REQUIRE(!set_handle->contains_globally_committed(k2));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read committed removals");
      {
        auto tx = kv_store.create_tx();
        auto set_handle = tx.ro(set);
        // Removal is still only locally committed
        REQUIRE(set_handle->contains_globally_committed(k1));
        REQUIRE(!set_handle->contains_globally_committed(k2));
      }
      kv_store.compact(kv_store.current_version());
      {
        auto tx = kv_store.create_tx();
        auto set_handle = tx.ro(set);
        // Removal is now globally committed
        REQUIRE(!set_handle->contains_globally_committed(k1));
        REQUIRE(!set_handle->contains_globally_committed(k2));
      }
    }

    {
      INFO("Hooks");

      kv_store.compact(kv_store.current_version()); // Flush global hook

      std::vector<Set::Write> local_writes;
      std::vector<Set::Write> global_writes;

      auto map_hook = [&](
                        ccf::kv::Version v,
                        const Set::Write& w) -> ccf::kv::ConsensusHookPtr {
        local_writes.push_back(w);
        return ccf::kv::ConsensusHookPtr(nullptr);
      };
      auto global_hook = [&](ccf::kv::Version v, const Set::Write& w) {
        global_writes.push_back(w);
      };

      kv_store.set_map_hook(set.get_name(), set.wrap_map_hook(map_hook));
      kv_store.set_global_hook(
        set.get_name(), set.wrap_commit_hook(global_hook));

      {
        INFO("Insertion only");

        auto tx = kv_store.create_tx();
        auto set_handle = tx.rw(set);
        set_handle->insert(k1);
        set_handle->insert(k2);
        set_handle->remove(k2);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        REQUIRE(global_writes.size() == 0);
        REQUIRE(local_writes.size() == 1);
        const auto& latest_writes = local_writes.front();
        REQUIRE(latest_writes.at(k1).has_value());
        REQUIRE(!latest_writes.at(k2).has_value());
        REQUIRE(latest_writes.size() == 2);

        local_writes.clear();
      }

      {
        INFO("Insertion and removal");

        auto tx = kv_store.create_tx();
        auto set_handle = tx.rw(set);
        set_handle->remove(k1);
        set_handle->insert(k2);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        REQUIRE(local_writes.size() == 1);
        const auto& latest_writes = local_writes.front();
        REQUIRE(latest_writes.size() == 2);
        REQUIRE(!latest_writes.at(k1).has_value());
        REQUIRE(latest_writes.at(k2).has_value());

        local_writes.clear();
      }

      {
        INFO("Global hook");

        auto tx = kv_store.create_tx();
        auto set_handle = tx.rw(set);
        set_handle->insert(k1);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        kv_store.compact(kv_store.current_version());

        REQUIRE(global_writes.size() == 4);
        REQUIRE(global_writes.at(0).size() == 2);
        REQUIRE(!global_writes.at(0).at(k1).has_value());
        REQUIRE(!global_writes.at(0).at(k2).has_value());
        REQUIRE(global_writes.at(1).size() == 2);
        REQUIRE(global_writes.at(1).at(k1).has_value());
        REQUIRE(!global_writes.at(1).at(k2).has_value());
        REQUIRE(global_writes.at(2).size() == 2);
        REQUIRE(!global_writes.at(2).at(k1).has_value());
        REQUIRE(global_writes.at(2).at(k2).has_value());
        REQUIRE(global_writes.at(3).size() == 1);
        REQUIRE(global_writes.at(3).at(k1).has_value());
      }
    }
  }

  {
    INFO("ccf::kv::Value");
    using Value = ccf::kv::Value<std::string>;
    Value val1("public:value1");
    Value val2("public:value2");

    const auto v1 = "hello";
    const auto v2 = "world";
    const auto v3 = "saluton";

    {
      INFO("Read own writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.rw(val1);
      REQUIRE(!h1->has());
      h1->put(v1);
      REQUIRE(h1->has());
      REQUIRE(*h1->get() == v1);

      auto h2 = tx.rw(val2);
      REQUIRE(!h2->has());
      h2->put(v2);
      REQUIRE(h2->has());
      REQUIRE(*h2->get() == v2);

      h2->put(v3);
      REQUIRE(h2->has());
      REQUIRE(*h2->get() == v3);

      h2->clear();
      REQUIRE(!h2->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read previous writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.ro(val1);
      REQUIRE(h1->has());
      REQUIRE(*h1->get() == v1);

      auto h2 = tx.rw(val2);
      REQUIRE(!h2->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Remove previous writes");
      auto tx = kv_store.create_tx();

      auto h1 = tx.rw(val1);
      REQUIRE(h1->has());
      h1->clear();
      REQUIRE(!h1->has());

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Hooks");

      kv_store.compact(kv_store.current_version()); // Flush global hook

      std::vector<Value::Write> local_writes;
      std::vector<Value::Write> global_writes;

      auto map_hook = [&](
                        ccf::kv::Version v,
                        const Value::Write& w) -> ccf::kv::ConsensusHookPtr {
        local_writes.push_back(w);
        return ccf::kv::ConsensusHookPtr(nullptr);
      };
      auto global_hook = [&](ccf::kv::Version v, const Value::Write& w) {
        global_writes.push_back(w);
      };

      kv_store.set_map_hook(val1.get_name(), val1.wrap_map_hook(map_hook));
      kv_store.set_global_hook(
        val1.get_name(), val1.wrap_commit_hook(global_hook));

      {
        INFO("Local hook");

        {
          auto tx = kv_store.create_tx();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
          REQUIRE(local_writes.size() == 0); // Commit without puts
        }

        {
          auto tx = kv_store.create_tx();
          auto h1 = tx.rw(val1);
          h1->put(v1);
          h1->put(v2); // Override previous value
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

          REQUIRE(global_writes.size() == 0);
          REQUIRE(local_writes.size() == 1);
          auto latest_writes = local_writes.front();
          REQUIRE(latest_writes.value() == v2);
          local_writes.clear();
        }

        {
          auto tx = kv_store.create_tx();
          auto h1 = tx.rw(val1);
          h1->clear();
          REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

          REQUIRE(local_writes.size() == 1);
          auto latest_writes = local_writes.front();
          REQUIRE(!latest_writes.has_value());
          local_writes.clear();
        }
      }

      {
        INFO("Global hook");

        auto tx = kv_store.create_tx();
        auto h1 = tx.rw(val1);
        h1->put(v3);
        REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

        kv_store.compact(kv_store.current_version());

        REQUIRE(global_writes.size() == 4);
        REQUIRE(!global_writes.at(0).has_value());
        REQUIRE(global_writes.at(1).value() == v2);
        REQUIRE(!global_writes.at(2).has_value());
        REQUIRE(global_writes.at(3).value() == v3);
      }
    }
  }

  {
    // Sanity check that transactions can handle a mix of maps, sets, and values
    INFO("Mixed");

    using TMap = ccf::kv::Map<std::string, size_t>;
    using TSet = ccf::kv::Set<size_t>;
    ccf::kv::Value<std::string> map_name_val("public:map_name");
    ccf::kv::Value<std::string> set_name_val("public:set_name");

    constexpr auto n_entries = 10;

    {
      INFO("Writing");
      auto tx = kv_store.create_tx();

      auto map_name_handle = tx.rw(map_name_val);
      map_name_handle->put("public:my_test_map");

      auto set_name_handle = tx.rw(set_name_val);
      set_name_handle->put("public:values_from_my_test_map");

      auto map_handle = tx.rw<TMap>(*map_name_handle->get());
      auto set_handle = tx.rw<TSet>(*set_name_handle->get());
      for (size_t i = 0; i < n_entries; ++i)
      {
        const auto n = i * i;
        const char c[2] = {(char)('A' + i), 0};
        map_handle->put(std::string(c), n);
        set_handle->insert(n);
      }

      REQUIRE(map_handle->size() == n_entries);
      REQUIRE(set_handle->size() == n_entries);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Read and modify");
      auto tx = kv_store.create_tx();

      auto map_name_handle = tx.rw(map_name_val);
      REQUIRE(map_name_handle->has());

      auto set_name_handle = tx.rw(set_name_val);
      REQUIRE(set_name_handle->has());

      auto map_handle = tx.rw<TMap>(*map_name_handle->get());
      auto set_handle = tx.rw<TSet>(*set_name_handle->get());

      REQUIRE(map_handle->size() == n_entries);
      REQUIRE(set_handle->size() == n_entries);

      map_handle->foreach(
        [&map_handle, &set_handle](const std::string& k, const size_t& v) {
          REQUIRE(set_handle->contains(v));

          if (k[0] % 3 == 0)
          {
            map_handle->remove(k);
            set_handle->remove(v);

            const auto s = k + k;
            const auto n = ~v;
            map_handle->put(s, n);
            set_handle->insert(n);
          }

          return true;
        });

      REQUIRE(map_handle->size() == n_entries);
      REQUIRE(set_handle->size() == n_entries);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }
}

struct CustomUnitCreator
{
  static ccf::kv::serialisers::SerialisedEntry get()
  {
    ccf::kv::serialisers::SerialisedEntry e;

    for (size_t i = 0; i < 42; ++i)
    {
      e.push_back(i);
    }

    return e;
  }
};

TEST_CASE("serialisation of Unit type")
{
  const auto value_name = "public:aa";
  const auto set_name = "public:bb";

  const auto v1 = "hello";
  const auto v2 = "world";
  const auto v3 = "saluton";

  {
    INFO("The default unit type allows migration to/from a ccf::kv::Map");

    using TValue = ccf::kv::RawCopySerialisedValue<std::string>;
    using TValueEquivalent = ccf::kv::RawCopySerialisedMap<size_t, std::string>;

    using TSet = ccf::kv::RawCopySerialisedSet<std::string>;
    using TSetEquivalent = ccf::kv::RawCopySerialisedMap<std::string, size_t>;

    ccf::kv::Store kv_store;
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    kv_store.set_encryptor(encryptor);

    {
      auto tx = kv_store.create_tx();

      auto val_handle = tx.rw<TValueEquivalent>(value_name);
      val_handle->put(0, v1); // Will be visible in TValue handle
      val_handle->put(1, v2); // Won't be

      auto set_handle = tx.rw<TSetEquivalent>(set_name);
      set_handle->put(v1, 0); // Will be visible in TSet handle
      set_handle->put(v2, 1); // Will be visible in TSet handle, but would be
                              // written with different value

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();

      auto val_handle = tx.rw<TValue>(value_name);
      REQUIRE(val_handle->has());
      REQUIRE(*val_handle->get() == v1);
      val_handle->put(v3);

      auto set_handle = tx.rw<TSet>(set_name);
      REQUIRE(set_handle->contains(v1));
      REQUIRE(set_handle->contains(v2));
      set_handle->insert(v2);
      set_handle->insert(v3);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();

      auto val_handle = tx.rw<TValueEquivalent>(value_name);
      REQUIRE(val_handle->has(0));
      REQUIRE(*val_handle->get(0) == v3);
      REQUIRE(val_handle->has(1));
      REQUIRE(*val_handle->get(1) == v2);

      auto set_handle = tx.rw<TSetEquivalent>(set_name);
      REQUIRE(set_handle->has(v1));
      REQUIRE(*set_handle->get(v1) == 0);
      REQUIRE(set_handle->has(v2));
      REQUIRE(*set_handle->get(v2) == 0);
      REQUIRE(set_handle->has(v3));
      REQUIRE(*set_handle->get(v3) == 0);

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }

  {
    INFO("Custom UnitCreators produce distinct ledger entries");

    using ValueA = ccf::kv::TypedValue<
      std::string,
      ccf::kv::serialisers::BlitSerialiser<std::string>,
      ccf::kv::serialisers::ZeroBlitUnitCreator>;
    std::vector<uint8_t> entry_a;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      ccf::kv::Store kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto val_handle = tx.rw<ValueA>(value_name);
      val_handle->put(v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      entry_a = e.value();
    }

    using ValueB = ccf::kv::TypedValue<
      std::string,
      ccf::kv::serialisers::BlitSerialiser<std::string>,
      ccf::kv::serialisers::EmptyUnitCreator>;
    std::vector<uint8_t> entry_b;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      ccf::kv::Store kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto val_handle = tx.rw<ValueB>(value_name);
      val_handle->put(v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      entry_b = e.value();
    }

    using ValueC = ccf::kv::TypedValue<
      std::string,
      ccf::kv::serialisers::BlitSerialiser<std::string>,
      CustomUnitCreator>;
    std::vector<uint8_t> entry_c;
    {
      auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
      ccf::kv::Store kv_store;
      auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
      kv_store.set_encryptor(encryptor);
      kv_store.set_consensus(consensus);
      auto tx = kv_store.create_tx();
      auto val_handle = tx.rw<ValueC>(value_name);
      val_handle->put(v1);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      const auto e = consensus->get_latest_data();
      REQUIRE(e.has_value());
      entry_c = e.value();
    }

    REQUIRE(entry_a != entry_b);
    REQUIRE(entry_a != entry_c);
    REQUIRE(entry_b != entry_c);
  }
}

TEST_CASE("multiple handles")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  MapTypes::NumString map("public:map");

  constexpr auto k = 42;
  constexpr auto v1 = "hello";
  constexpr auto v2 = "saluton";

  auto tx = kv_store.create_tx();

  auto h1 = tx.ro(map);
  auto h2 = tx.rw(map);
  auto h3 = tx.wo(map);

  REQUIRE(!h1->has(k));
  REQUIRE(!h2->has(k));

  h2->put(k, v1);

  REQUIRE(h1->has(k));
  REQUIRE(*h1->get(k) == v1);
  REQUIRE(h2->has(k));
  REQUIRE(*h2->get(k) == v1);

  h3->put(k, v2);

  REQUIRE(h1->has(k));
  REQUIRE(*h1->get(k) == v2);
  REQUIRE(h2->has(k));
  REQUIRE(*h2->get(k) == v2);
}

TEST_CASE("clear")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";

  const auto v = "v";

  {
    INFO("Setting committed state");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  SUBCASE("Basic")
  {
    {
      INFO("Clear removes all entries");
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put(k2, v);

      REQUIRE(handle->has(k1));
      REQUIRE(handle->has(k2));

      handle->clear();

      REQUIRE(!handle->has(k1));
      REQUIRE(!handle->has(k2));

      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      INFO("Clear is committed");
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);

      REQUIRE(!handle->has(k1));
      REQUIRE(!handle->has(k2));
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }

  SUBCASE("Clear conflicts correctly")
  {
    auto tx1 = kv_store.create_tx();
    auto handle1 = tx1.rw(map);
    handle1->clear();

    INFO("Another transaction creates a key and commits");
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->put(k2, v);
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    INFO("clear() conflicts and must be retried");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }
}

TEST_CASE("get_version_of_previous_write")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";
  const auto k3 = "k3";

  const auto v1 = "v1";
  const auto v2 = "v2";
  const auto v3 = "v3";

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v1);
    handle->put(k2, v1);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto first_version = kv_store.current_version();

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k1, v2);
    handle->remove(k2);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto second_version = kv_store.current_version();

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    {
      auto tx_other = kv_store.create_tx();
      auto handle = tx_other.rw(map);
      handle->put(k2, v3);
      tx_other.commit();
    }

    {
      // We don't see effects of tx_other because we started executing earlier.
      // k1 is at second_version
      const auto ver1 = handle->get_version_of_previous_write(k1);
      REQUIRE(ver1.has_value());
      REQUIRE(ver1.value() == second_version);

      // k2 was removed, so has no version...
      REQUIRE(!handle->get_version_of_previous_write(k2).has_value());

      // ...just like k3 which was never written
      REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

      {
        INFO("Reading from these keys doesn't change this");
        handle->has(k1);
        handle->has(k2);
        handle->has(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

        handle->get(k1);
        handle->get(k2);
        handle->get(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());
      }

      SUBCASE("Writing to these keys doesn't change this")
      {
        handle->put(k1, v3);
        handle->put(k2, v3);
        handle->put(k3, v3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());

        handle->remove(k1);
        handle->remove(k2);
        handle->remove(k3);

        REQUIRE(
          handle->get_version_of_previous_write(k1).value() == second_version);
        REQUIRE(!handle->get_version_of_previous_write(k2).has_value());
        REQUIRE(!handle->get_version_of_previous_write(k3).has_value());
      }

      // This conflicts with tx_other so is not committed
      REQUIRE(tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
    }
  }

  const auto third_version = kv_store.current_version();

  {
    INFO("Version is per-key");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    const auto ver1 = handle->get_version_of_previous_write(k1);
    const auto ver2 = handle->get_version_of_previous_write(k2);

    REQUIRE(ver1.has_value());
    REQUIRE(ver2.has_value());

    REQUIRE(ver1.value() == second_version);
    REQUIRE(ver2.value() == third_version);
  }
}

TEST_CASE("size")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  const auto k1 = "k1";
  const auto k2 = "k2";
  const auto k3 = "k3";

  const auto v = "v";
  const auto vv = "vv";

  {
    INFO("Only local modifications");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    REQUIRE(handle->size() == 0);
    handle->put(k1, v);
    REQUIRE(handle->size() == 1);
    handle->remove(k2);
    REQUIRE(handle->size() == 1);
    handle->remove(k1);
    REQUIRE(handle->size() == 0);
    handle->put(k2, v);
    REQUIRE(handle->size() == 1);
    handle->put(k2, vv);
    REQUIRE(handle->size() == 1);
    handle->put(k1, v);
    REQUIRE(handle->size() == 2);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Combined with committed state");
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    REQUIRE(handle->size() == 2);
    handle->put(k2, v);
    REQUIRE(handle->size() == 2);
    handle->put(k3, v);
    REQUIRE(handle->size() == 3);
    handle->remove(k1);
    REQUIRE(handle->size() == 2);
    handle->remove(k2);
    REQUIRE(handle->size() == 1);
    handle->remove(k3);
    REQUIRE(handle->size() == 0);

    {
      INFO("size() is only affected by current transaction");
      auto tx2 = kv_store.create_tx();
      auto handle = tx2.rw(map);

      REQUIRE(handle->size() == 2);
      handle->remove(k2);
      REQUIRE(handle->size() == 1);
    }

    REQUIRE(handle->size() == 0);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Sanity check");
    for (size_t i = 0; i < 20; ++i)
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      for (size_t j = 0; j < 1'000; ++j)
      {
        const auto key = std::to_string(rand() % 10'000);
        if (rand() % 4 == 0)
        {
          handle->remove(key);
        }
        else
        {
          handle->put(key, v);
        }
      }

      const auto claimed_size = handle->size();
      size_t manual_size = 0;
      handle->foreach([&manual_size](const auto&, const auto&) {
        ++manual_size;
        return true;
      });

      REQUIRE(claimed_size == manual_size);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }
  }
}

TEST_CASE("foreach")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  std::map<std::string, std::string> iterated_entries;

  auto store_iterated =
    [&iterated_entries](const auto& key, const auto& value) {
      auto it = iterated_entries.find(key);
      REQUIRE(it == iterated_entries.end());
      iterated_entries[key] = value;
      return true;
    };

  SUBCASE("Empty map")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading own writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    handle->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");

    iterated_entries.clear();

    INFO("Uncommitted writes from other txs are not visible");
    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.empty());
  }

  SUBCASE("Reading committed writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 2);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "value2");
  }

  SUBCASE("Mix of committed and own writes")
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key1", "value1");
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx2 = kv_store.create_tx();
    auto handle2 = tx2.rw(map);
    handle2->put("key2", "replaced2");
    handle2->put("key3", "value3");
    handle2->foreach(store_iterated);
    REQUIRE(iterated_entries.size() == 3);
    REQUIRE(iterated_entries["key1"] == "value1");
    REQUIRE(iterated_entries["key2"] == "replaced2");
    REQUIRE(iterated_entries["key3"] == "value3");
  }

  SUBCASE("Deletions")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->put("key3", "value3");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->remove("key1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 2);
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      handle->remove("key2");
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 1);
      REQUIRE(iterated_entries["key3"] == "value3");

      iterated_entries.clear();

      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->foreach(store_iterated);
      REQUIRE(iterated_entries.size() == 3);
      REQUIRE(iterated_entries["key1"] == "value1");
      REQUIRE(iterated_entries["key2"] == "value2");
      REQUIRE(iterated_entries["key3"] == "value3");
    }
  }

  SUBCASE("Early termination")
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->put("key3", "value3");
      size_t ctr = 0;
      handle->foreach([&ctr](const auto& key, const auto& value) {
        ++ctr;
        return ctr < 2; // Continue after the first, but not the second (so
                        // never see the third)
      });
      REQUIRE(ctr == 2);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key4", "value4");
      handle->put("key5", "value5");

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 2; //< See only committed state
        });
        REQUIRE(ctr == 2);
      }

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 4; //< See mix of old state and new writes
        });
        REQUIRE(ctr == 4);
      }

      {
        size_t ctr = 0;
        handle->foreach([&ctr](const auto&, const auto&) {
          ++ctr;
          return ctr < 100; //< See as much as possible
        });
        REQUIRE(ctr == 5);
      }
    }
  }
}

// The purpose of foreach_key and foreach_value is avoiding deserialisation of
// values/keys (respectively) when they're not needed. To confirm that they're
// not deserialised, we use a custom serialiser which will throw if ever asked
// to deserialise.
template <typename T>
struct NoDeserialise
{
  static ccf::kv::serialisers::SerialisedEntry to_serialised(const T& t)
  {
    return ccf::kv::serialisers::JsonSerialiser<T>::to_serialised(t);
  }

  static T from_serialised(const ccf::kv::serialisers::SerialisedEntry& s)
  {
    throw std::logic_error("This deserialiser should not be called");
  }
};

TEST_CASE("foreach_key")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  ccf::kv::MapSerialisedWith<
    std::string,
    std::string,
    ccf::kv::serialisers::JsonSerialiser,
    NoDeserialise>
    map("public:map");

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("k1", "v1");
    handle->put("k2", "v2");
    handle->put("k3", "v3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE_NOTHROW(handle->foreach_key([](const std::string& k) {
      REQUIRE(k.find('k') != std::string::npos);
      return true;
    }));

    // Sanity check: Confirm that deserialising any value would throw
    REQUIRE_THROWS(handle->foreach(
      [](const std::string& k, const std::string& v) { return true; }));
    REQUIRE_THROWS(handle->get("k1"));
  }
}

TEST_CASE("foreach_value")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);

  ccf::kv::MapSerialisedWith<
    std::string,
    std::string,
    NoDeserialise,
    ccf::kv::serialisers::JsonSerialiser>
    map("public:map");

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("k1", "v1");
    handle->put("k2", "v2");
    handle->put("k3", "v3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    REQUIRE_NOTHROW(handle->foreach_value([](const std::string& v) {
      REQUIRE(v.find('v') != std::string::npos);
      return true;
    }));

    // Sanity check: Confirm that deserialising any key would throw
    REQUIRE_THROWS(handle->foreach(
      [](const std::string& k, const std::string& v) { return true; }));
  }
}

TEST_CASE("Modifications during foreach iteration")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::NumString map("public:map");

  const auto value1 = "foo";
  const auto value2 = "bar";

  std::set<size_t> keys;
  {
    INFO("Insert initial keys");

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    for (size_t i = 0; i < 60; ++i)
    {
      keys.insert(i);
      handle->put(i, value1);
    }

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto tx = kv_store.create_tx();
  auto handle = tx.rw(map);

  // 5 types of key:
  // 1) previously committed and unmodified
  const auto initial_keys_size = keys.size();
  const auto keys_per_category = keys.size() / 3;
  // We do nothing to the first keys_per_category keys

  // 2) previously committed and had their values changed
  for (size_t i = keys_per_category; i < 2 * keys_per_category; ++i)
  {
    keys.insert(i);
    handle->put(i, value2);
  }

  // 3) previously committed and now removed
  for (size_t i = 2 * keys_per_category; i < initial_keys_size; ++i)
  {
    keys.erase(i);
    handle->remove(i);
  }

  // 4) newly written
  for (size_t i = initial_keys_size; i < initial_keys_size + keys_per_category;
       ++i)
  {
    keys.insert(i);
    handle->put(i, value2);
  }

  // 5) newly written and then removed
  for (size_t i = initial_keys_size + keys_per_category;
       i < initial_keys_size + 2 * keys_per_category;
       ++i)
  {
    keys.insert(i);
    handle->put(i, value2);

    keys.erase(i);
    handle->remove(i);
  }

  size_t keys_seen = 0;
  const auto expected_keys_seen = keys.size();

  SUBCASE("Removing current key while iterating")
  {
    auto should_remove = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    handle->foreach(
      [&handle, &keys, &keys_seen, should_remove](const auto& k, const auto&) {
        ++keys_seen;
        const auto it = keys.find(k);
        REQUIRE(it != keys.end());

        // Remove a 'random' set of keys while iterating
        if (should_remove(k))
        {
          handle->remove(k);
          keys.erase(it);
        }

        return true;
      });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check all expected keys are still there...
    handle->foreach([&keys, should_remove](const auto& k, const auto&) {
      REQUIRE(!should_remove(k));
      const auto it = keys.find(k);
      REQUIRE(it != keys.end());
      keys.erase(it);
      return true;
    });

    // ...and nothing else
    REQUIRE(keys.empty());
  }

  SUBCASE("Removing other keys while iterating")
  {
    auto should_remove = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    std::optional<size_t> removal_trigger = std::nullopt;

    handle->foreach(
      [&handle, &keys, &keys_seen, &removal_trigger, should_remove](
        const auto& k, const auto&) {
        ++keys_seen;

        // The first time we find a removable, remove _all the others_ (not
        // ourself!)
        if (should_remove(k) && !removal_trigger.has_value())
        {
          REQUIRE(!removal_trigger.has_value());
          removal_trigger = k;

          auto remove_it = keys.begin();
          while (remove_it != keys.end())
          {
            const auto n = *remove_it;
            if (should_remove(n) && n != k)
            {
              handle->remove(n);
              remove_it = keys.erase(remove_it);
            }
            else
            {
              ++remove_it;
            }
          }
        }

        return true;
      });

    REQUIRE(keys_seen == expected_keys_seen);

    REQUIRE(removal_trigger.has_value());

    // Check all expected keys are still there...
    handle->foreach(
      [&keys, removal_trigger, should_remove](const auto& k, const auto&) {
        const auto should_be_here =
          !should_remove(k) || k == removal_trigger.value();
        REQUIRE(should_be_here);
        const auto it = keys.find(k);
        REQUIRE(it != keys.end());
        keys.erase(it);
        return true;
      });

    // ...and nothing else
    REQUIRE(keys.empty());
  }

  static constexpr auto value3 = "baz";

  SUBCASE("Modifying and adding other keys while iterating")
  {
    auto should_modify = [](size_t n) { return n % 3 == 0 || n % 5 == 0; };

    std::set<size_t> updated_keys;

    handle->foreach([&handle, &keys, &keys_seen, &updated_keys, should_modify](
                      const auto& k, const auto& v) {
      ++keys_seen;

      if (should_modify(k))
      {
        // Modify ourselves
        handle->put(k, value3);
        updated_keys.insert(k);

        // Modify someone else ('before' and 'after' are guesses - iteration
        // order is undefined!)
        const auto before = k / 2;
        handle->put(before, value3);
        keys.insert(before);
        updated_keys.insert(before);

        const auto after = k * 2;
        handle->put(after, value3);
        keys.insert(after);
        updated_keys.insert(after);

        // Note discrepancy with externally visible value
        const auto visible_v = handle->get(k);
        REQUIRE(visible_v.has_value());
        REQUIRE(visible_v.value() == value3);
        REQUIRE(visible_v.value() != v); // !!
      }

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check all expected keys are still there...
    handle->foreach([&keys, &updated_keys](const auto& k, const auto& v) {
      const auto updated_it = updated_keys.find(k);
      if (updated_it != updated_keys.end())
      {
        REQUIRE(v == value3);
        updated_keys.erase(updated_it);
      }
      else
      {
        REQUIRE(v != value3);
      }

      const auto it = keys.find(k);
      if (it != keys.end())
      {
        keys.erase(it);
      }

      return true;
    });

    // ...and nothing else
    REQUIRE(keys.empty());
    REQUIRE(updated_keys.empty());
  }

  SUBCASE("Rewriting to new keys")
  {
    // Rewrite map, placing each value at a new key
    handle->foreach([&handle, &keys_seen](const auto& k, const auto& v) {
      ++keys_seen;

      handle->remove(k);

      const auto new_key = k + 1000;
      REQUIRE(!handle->has(new_key));
      handle->put(new_key, v);

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);

    // Check map contains only new keys, and the same count
    keys_seen = 0;
    handle->foreach([&handle, &keys, &keys_seen](const auto& k, const auto& v) {
      ++keys_seen;

      REQUIRE(keys.find(k) == keys.end());

      return true;
    });

    REQUIRE(keys_seen == expected_keys_seen);
  }
}

TEST_CASE("Read-only tx")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto invalid_key = "invalid_key";
  constexpr auto v1 = "value1";

  INFO("Write some keys");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    auto v = handle->get(k);
    REQUIRE(!v.has_value());
    handle->put(k, v1);
    auto va = handle->get(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Do only reads with an overpowered Tx");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map);
    REQUIRE(handle->has(k));
    const auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    REQUIRE(!handle->has(invalid_key));
    const auto invalid_v = handle->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // handle->put(k, v1);
    // handle->remove(k);
  }

  INFO("Read with read-only tx");
  {
    auto tx = kv_store.create_read_only_tx();
    auto handle = tx.ro(map);
    REQUIRE(handle->has(k));
    const auto v = handle->get(k);
    REQUIRE(v.has_value());
    REQUIRE(v.value() == v1);

    REQUIRE(!handle->has(invalid_key));
    const auto invalid_v = handle->get(invalid_key);
    REQUIRE(!invalid_v.has_value());

    // The following won't compile:
    // handle->put(k, v1);
    // handle->remove(k);
  }

  INFO("Write-only handles");
  {
    auto tx = kv_store.create_tx();
    auto handle = tx.wo(map);

    handle->put(k, v1);
    handle->remove(k);

    // The following won't compile:
    // handle->has(k);
    // handle->get(k);
    // handle->foreach([](const auto&, const auto&) {});
  }
}

TEST_CASE("Rollback and compact")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  constexpr auto k = "key";
  constexpr auto v1 = "value1";

  INFO("Do not read transactions that have been rolled back");
  {
    auto tx = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.rollback({kv_store.commit_view(), 0}, kv_store.commit_view());
    auto handle2 = tx2.rw(map);
    auto v = handle2->get(k);
    REQUIRE(!v.has_value());
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Read committed key");
  {
    auto tx = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put(k, v1);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    auto handle2 = tx2.rw(map);
    auto va = handle2->get_globally_committed(k);
    REQUIRE(va.has_value());
    REQUIRE(va.value() == v1);
  }

  INFO("Read deleted committed key");
  {
    auto tx = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->remove(k);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    kv_store.compact(kv_store.current_version());

    auto handle2 = tx2.rw(map);
    auto va = handle2->get_globally_committed(k);
    REQUIRE(!va.has_value());
  }
}

TEST_CASE("Local commit hooks")
{
  using Write = MapTypes::StringString::Write;
  std::vector<Write> local_writes;
  std::vector<Write> global_writes;

  auto map_hook =
    [&](ccf::kv::Version v, const Write& w) -> ccf::kv::ConsensusHookPtr {
    local_writes.push_back(w);
    return ccf::kv::ConsensusHookPtr(nullptr);
  };
  auto global_hook = [&](ccf::kv::Version v, const Write& w) {
    global_writes.push_back(w);
  };

  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  constexpr auto map_name = "public:map";
  MapTypes::StringString map(map_name);
  kv_store.set_map_hook(map_name, map.wrap_map_hook(map_hook));
  kv_store.set_global_hook(map_name, map.wrap_commit_hook(global_hook));

  INFO("Write with hooks");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key1", "value1");
      handle->put("key2", "value2");
      handle->remove("key2");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(global_writes.size() == 0);
      REQUIRE(local_writes.size() == 1);
      const auto& latest_writes = local_writes.back();
      REQUIRE(latest_writes.at("key1").has_value());
      REQUIRE(latest_writes.at("key1").value() == "value1");
      REQUIRE(!latest_writes.at("key2").has_value());
      REQUIRE(latest_writes.size() == 2);
      local_writes.clear();
    }

    {
      REQUIRE(local_writes.size() == 0);
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->remove("key1");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(global_writes.size() == 0);
      REQUIRE(local_writes.size() == 1);
      const auto& latest_writes = local_writes.back();
      INFO("Removals are seen");
      REQUIRE(latest_writes.find("key1") != latest_writes.end());
      REQUIRE(latest_writes.at("key1") == std::nullopt);

      local_writes.clear();
    }
  }

  INFO("Write without hooks");
  {
    kv_store.unset_map_hook(map_name);
    kv_store.unset_global_hook(map_name);

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("key2", "value2");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(local_writes.size() == 0);
    REQUIRE(global_writes.size() == 0);
  }

  INFO("Write with hook again");
  {
    kv_store.set_map_hook(map_name, map.wrap_map_hook(map_hook));
    kv_store.set_global_hook(map_name, map.wrap_commit_hook(global_hook));

    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->remove("key2");
    handle->put("key3", "value3");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(global_writes.size() == 0);
    REQUIRE(local_writes.size() == 1);
    const auto& latest_writes = local_writes.front();
    INFO("Old writes are not included");
    REQUIRE(latest_writes.find("key1") == latest_writes.end());
    INFO("Visible removals are included");
    const auto it2 = latest_writes.find("key2");
    REQUIRE(it2 != latest_writes.end());
    REQUIRE(!it2->second.has_value());
    const auto it3 = latest_writes.find("key3");
    REQUIRE(it3 != latest_writes.end());
    REQUIRE(it3->second.has_value());
    REQUIRE(it3->second.value() == "value3");
    REQUIRE(latest_writes.size() == 2);

    local_writes.clear();
  }
}

TEST_CASE("Global commit hooks")
{
  using Write = MapTypes::StringString::Write;

  struct GlobalHookInput
  {
    ccf::kv::Version version;
    Write writes;
  };

  std::vector<GlobalHookInput> global_writes;

  auto global_hook = [&](ccf::kv::Version v, const Write& w) {
    global_writes.emplace_back(GlobalHookInput({v, w}));
  };

  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  using MapT = ccf::kv::Map<std::string, std::string>;
  MapT map_with_hook("public:map_with_hook");
  kv_store.set_global_hook(
    map_with_hook.get_name(), map_with_hook.wrap_commit_hook(global_hook));

  MapT map_no_hook("public:map_no_hook");

  INFO("Compact an empty store");
  {
    kv_store.compact(0);

    REQUIRE(global_writes.size() == 0);
  }

  SUBCASE("Compact one transaction")
  {
    auto tx1 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(1);

    REQUIRE(global_writes.size() == 1);
    const auto& latest_writes = global_writes.front();
    REQUIRE(latest_writes.version == 1);
    const auto it1 = latest_writes.writes.find("key1");
    REQUIRE(it1 != latest_writes.writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
  }

  SUBCASE("Compact beyond the last map version")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto tx3 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    handle_hook = tx2.rw(map_with_hook);
    handle_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto compact_version = kv_store.current_version();

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto handle_no_hook = tx3.rw(map_no_hook);
    handle_no_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 2);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
    const auto it2 = global_writes.at(1).writes.find("key2");
    REQUIRE(it2 != global_writes.at(1).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");
  }

  SUBCASE("Compact in between two map versions")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto tx3 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    // This does not affect map_with_hook but still increments the current
    // version of the store
    auto handle_no_hook = tx2.rw(map_no_hook);
    handle_no_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    const auto compact_version = kv_store.current_version();

    handle_hook = tx3.rw(map_with_hook);
    handle_hook->put("key3", "value3");
    REQUIRE(tx3.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(compact_version);

    // Only the changes made to map_with_hook should be passed to the global
    // hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 1);
    const auto it1 = global_writes.at(0).writes.find("key1");
    REQUIRE(it1 != global_writes.at(0).writes.end());
    REQUIRE(it1->second.has_value());
    REQUIRE(it1->second.value() == "value1");
  }

  SUBCASE("Compact twice")
  {
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();
    auto handle_hook = tx1.rw(map_with_hook);
    handle_hook->put("key1", "value1");
    REQUIRE(tx1.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(kv_store.current_version());
    global_writes.clear();

    handle_hook = tx2.rw(map_with_hook);
    handle_hook->put("key2", "value2");
    REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);

    kv_store.compact(kv_store.current_version());

    // Only writes since the last compact are passed to the global hook
    REQUIRE(global_writes.size() == 1);
    REQUIRE(global_writes.at(0).version == 2);
    const auto it2 = global_writes.at(0).writes.find("key2");
    REQUIRE(it2 != global_writes.at(0).writes.end());
    REQUIRE(it2->second.has_value());
    REQUIRE(it2->second.value() == "value2");
  }
}

TEST_CASE("Deserialising from other Store")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::kv::Store store;
  store.set_encryptor(encryptor);

  MapTypes::NumString public_map("public:public");
  MapTypes::NumString private_map("private");
  auto tx1 = store.create_reserved_tx(store.next_txid());
  auto handle1 = tx1.rw(public_map);
  auto handle2 = tx1.rw(private_map);
  handle1->put(42, "aardvark");
  handle2->put(14, "alligator");
  auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
    tx1.commit_reserved();
  auto& success = success_;
  auto& data = data_;
  REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

  ccf::kv::Store clone;
  clone.set_encryptor(encryptor);

  REQUIRE(clone.deserialize(data)->apply() == ccf::kv::ApplyResult::PASS);
}

TEST_CASE("Deserialise return status")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  store.set_encryptor(encryptor);

  ccf::Signatures signatures(ccf::Tables::SIGNATURES);
  ccf::SerialisedMerkleTree serialised_tree(
    ccf::Tables::SERIALISED_MERKLE_TREE);

  ccf::Nodes nodes(ccf::Tables::NODES);
  MapTypes::NumNum data("public:data");

  constexpr auto default_curve = ccf::crypto::CurveID::SECP384R1;
  auto kp = ccf::crypto::make_key_pair(default_curve);

  auto history = std::make_shared<ccf::NullTxHistory>(
    store, ccf::kv::test::PrimaryNodeId, *kp);
  store.set_history(history);

  {
    auto tx = store.create_reserved_tx(store.next_txid());
    auto data_handle = tx.rw(data);
    data_handle->put(42, 42);
    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(store.deserialize(data)->apply() == ccf::kv::ApplyResult::PASS);
  }

  {
    auto tx = store.create_reserved_tx(store.next_txid());
    auto sig_handle = tx.rw(signatures);
    auto tree_handle = tx.rw(serialised_tree);
    ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, 2);
    sig_handle->put(sigv);
    tree_handle->put({});
    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(
      store.deserialize(data)->apply() == ccf::kv::ApplyResult::PASS_SIGNATURE);
  }

  INFO("Signature transactions with additional contents should fail");
  {
    auto tx = store.create_reserved_tx(store.next_txid());
    auto sig_handle = tx.rw(signatures);
    auto data_handle = tx.rw(data);
    ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, 2);
    sig_handle->put(sigv);
    data_handle->put(43, 43);
    auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
      tx.commit_reserved();
    auto& success = success_;
    auto& data = data_;
    REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

    REQUIRE(store.deserialize(data)->apply() == ccf::kv::ApplyResult::FAIL);
  }
}

TEST_CASE("Map swap between stores")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::kv::Store s1;
  s1.set_encryptor(encryptor);

  ccf::kv::Store s2;
  s2.set_encryptor(encryptor);

  MapTypes::NumNum d("data");
  MapTypes::NumNum pd("public:data");

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(d);
    v->put(42, 42);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pd);
    v->put(14, 14);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  const auto target_version = s1.current_version();
  while (s2.current_version() < target_version)
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(d);
    v->put(41, 41);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  s2.swap_private_maps(s1);

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(d);
    auto val = v->get(41);
    REQUIRE_FALSE(v->get(42).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 41);
  }

  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pd);
    auto val = v->get(14);
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 14);
  }

  {
    auto tx = s2.create_tx();
    auto v = tx.rw(d);
    auto val = v->get(42);
    REQUIRE_FALSE(v->get(41).has_value());
    REQUIRE(val.has_value());
    REQUIRE(val.value() == 42);
  }

  {
    auto tx = s2.create_tx();
    auto v = tx.rw(pd);
    REQUIRE_FALSE(v->get(14).has_value());
  }
}

TEST_CASE("Private recovery map swap")
{
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  ccf::kv::Store s1;
  s1.set_encryptor(encryptor);
  MapTypes::NumNum priv1("private");
  MapTypes::NumString pub1("public:data");

  ccf::kv::Store s2;
  s2.set_encryptor(encryptor);
  MapTypes::NumNum priv2("private");
  MapTypes::NumString pub2("public:data");

  INFO("Populate s1 with public entries");
  // We compact twice, deliberately. A public KV during recovery
  // would have compacted some number of times.
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(42, "42");
    tx.commit();
  }
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(42, "43");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(44, "44");
    tx.commit();
  }
  s1.compact(s1.current_version());
  {
    auto tx = s1.create_tx();
    auto v = tx.rw(pub1);
    v->put(45, "45");
    tx.commit();
  }

  INFO("Populate s2 with private entries");
  // We compact only once, at a lower index than we did for the public
  // KV, which is what we expect during recovery of the private KV. We do expect
  // that the _entire_ private state is compacted
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(12, 12);
    tx.commit();
  }
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(13, 13);
    tx.commit();
  }
  s2.compact(s2.current_version());
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(14, 14);
    tx.commit();
  }
  {
    auto tx = s2.create_tx();
    auto v = tx.rw(priv2);
    v->put(15, 15);
    tx.commit();
  }

  INFO("Swap in private maps");
  REQUIRE(s1.current_version() == s2.current_version());
  REQUIRE_NOTHROW(s1.swap_private_maps(s2));

  INFO("Check state looks as expected in s1");
  {
    auto tx = s1.create_tx();
    auto priv = tx.rw(priv1);
    auto pub = tx.rw(pub1);
    {
      auto val = pub->get(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get(45);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "45");

      REQUIRE(s1.compacted_version() == 3);
    }
    {
      for (size_t i : {12, 13, 14, 15})
      {
        auto val = priv->get(i);
        REQUIRE(val.has_value());
        REQUIRE(val.value() == i);
      }
    }
  }

  INFO("Check committed state looks as expected in s1");
  {
    auto tx = s1.create_tx();
    auto priv = tx.rw(priv1);
    auto pub = tx.rw(pub1);
    {
      auto val = pub->get_globally_committed(42);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "43");

      val = pub->get_globally_committed(44);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == "44");

      val = pub->get_globally_committed(45);
      REQUIRE_FALSE(val.has_value());
    }
    {
      auto val = priv->get_globally_committed(12);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 12);

      val = priv->get_globally_committed(13);
      REQUIRE(val.has_value());
      REQUIRE(val.value() == 13);

      // Uncompacted state is visible, which is expected, but isn't
      // something that would happen in recovery (only compacted state
      // would be swapped in). There is deliberately no check for compacted
      // state later than the compact level on the public KV, as this is
      // impossible during recovery.
    }
  }
}

TEST_CASE("Conflict resolution")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString map("public:map");

  {
    // Ensure this map already exists, by making a prior write to it
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);
    handle->put("foo", "initial");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  auto try_write = [&](ccf::kv::Tx& tx, const std::string& s) {
    auto handle = tx.rw(map);

    // Introduce read-dependency
    handle->get("foo");
    handle->put("foo", s);

    handle->put(s, s);
  };

  auto confirm_state = [&](
                         const std::vector<std::string>& present,
                         const std::vector<std::string>& missing) {
    auto tx = kv_store.create_tx();
    auto handle = tx.rw(map);

    for (const auto& s : present)
    {
      const auto it = handle->get(s);
      REQUIRE(it.has_value());
      REQUIRE(handle->has(s));
      REQUIRE(it.value() == s);
    }

    for (const auto& s : missing)
    {
      const auto it = handle->get(s);
      REQUIRE(!it.has_value());
      REQUIRE(!handle->has(s));
    }
  };

  // Simulate parallel execution by interleaving tx steps
  auto tx1 = kv_store.create_tx();
  auto tx2 = kv_store.create_tx();

  // First transaction tries to write a value, depending on initial version
  try_write(tx1, "bar");

  {
    // A second transaction is committed, conflicting with the first
    try_write(tx2, "baz");
    const auto res2 = tx2.commit();
    REQUIRE(res2 == ccf::kv::CommitResult::SUCCESS);

    confirm_state({"baz"}, {"bar"});
  }

  // Trying to commit first transaction produces a conflict
  auto res1 = tx1.commit();
  REQUIRE(res1 == ccf::kv::CommitResult::FAIL_CONFLICT);
  confirm_state({"baz"}, {"bar"});

  // A third transaction just wants to read the value
  auto tx3 = kv_store.create_tx();
  auto handle3 = tx3.ro(map);
  REQUIRE(handle3->has("foo"));

  // First transaction is rerun on new object, producing different result
  tx1 = kv_store.create_tx();
  try_write(tx1, "buzz");

  // Expected results are committed
  res1 = tx1.commit();
  REQUIRE(res1 == ccf::kv::CommitResult::SUCCESS);
  confirm_state({"baz", "buzz"}, {"bar"});

  // Third transaction completes later, has no conflicts but reports the earlier
  // version it read
  auto res3 = tx3.commit();
  REQUIRE(res3 == ccf::kv::CommitResult::SUCCESS);

  REQUIRE(tx1.commit_version() > tx2.commit_version());
  REQUIRE(tx3.get_txid()->version >= tx2.get_txid()->version);

  // Re-running a _committed_ transaction is exceptionally bad
  REQUIRE_THROWS(tx1.commit());
  REQUIRE_THROWS(tx2.commit());
}

TEST_CASE("Conflict resolution - removals")
{
  enum class Cases : size_t
  {
    NoReads = 0,
    ReadSameKey,
    ReadOtherKey,
    WriteSameKey,
    WriteOtherKey,
    MAX
  };

  for (size_t i = 0; i < (size_t)Cases::MAX; ++i)
  {
    auto c = Cases(i);
    INFO("Considering case " << c);

    ccf::kv::Store kv_store;
    auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
    kv_store.set_encryptor(encryptor);
    MapTypes::StringString map("public:map");

    {
      // Ensure maps already exist, by making prior writes
      auto tx = kv_store.create_tx();
      tx.rw(map)->put("", "");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Simulate parallel execution by interleaving tx steps
    auto tx1 = kv_store.create_tx();
    auto tx2 = kv_store.create_tx();

    constexpr auto k = "key";

    auto handle_1 = tx1.rw(map);

    switch (c)
    {
      case Cases::NoReads:
      {
        break;
      }
      case Cases::ReadSameKey:
      {
        handle_1->has(k);
        break;
      }
      case Cases::ReadOtherKey:
      {
        handle_1->has("unrelated");
        break;
      }
      case Cases::WriteSameKey:
      {
        handle_1->put(k, "saluton");
        break;
      }
      case Cases::WriteOtherKey:
      {
        handle_1->put("unrelated", "saluton");
        break;
      }
      default:
      {
        throw std::logic_error("Unhandled");
        break;
      }
    }

    handle_1->remove(k);

    {
      auto handle = tx2.rw(map);
      handle->put(k, "hello");
      REQUIRE(tx2.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    const auto expected = c == Cases::ReadSameKey ?
      ccf::kv::CommitResult::FAIL_CONFLICT :
      ccf::kv::CommitResult::SUCCESS;

    CHECK_EQ(tx1.commit(), expected);

    auto tx3 = kv_store.create_tx();
    auto handle = tx3.rw(map);
    if (c == Cases::ReadSameKey)
    {
      const auto v = handle->get(k);
      CHECK(v.has_value());
      CHECK_EQ(v.value(), "hello");
    }
    else
    {
      // NB: In all of these cases, this remove has been applied _after_ tx2,
      // though it executed 'before'. This is because it has no
      // dependencies/conflicts with tx2, so it is safe to apply its removes on
      // the later state.
      CHECK(!handle->has(k));
      CHECK_GT(tx1.commit_version(), tx2.commit_version());
    }
  }
}

TEST_CASE("Cross-map conflicts")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringString source("public:source");
  MapTypes::StringString dest("public:dest");

  {
    INFO("Set initial state");

    auto tx = kv_store.create_tx();
    auto source_handle = tx.wo(source);
    source_handle->put("hello", "world");
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Start an operation copying a value across tables");
    auto copy_tx = kv_store.create_tx();
    {
      auto src_handle = copy_tx.ro(source);
      auto dst_handle = copy_tx.wo(dest);
      const auto v = src_handle->get("hello");
      REQUIRE(v.has_value());
      dst_handle->put("hello", v.value());
    }

    INFO(
      "Before the copy commits, another operation changes the source, and "
      "commits");
    {
      auto interfere_tx = kv_store.create_tx();
      auto src_handle = interfere_tx.wo(source);
      src_handle->put("hello", "alice");
      REQUIRE(interfere_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Copying operation should conflict on commit");
    REQUIRE(copy_tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }

  {
    INFO("Start an operation moving a value across tables");
    auto move_tx = kv_store.create_tx();
    {
      auto src_handle = move_tx.rw(source);
      auto dst_handle = move_tx.wo(dest);
      const auto v = src_handle->get("hello");
      REQUIRE(v.has_value());
      dst_handle->put("hello", v.value());

      // Unlike copy, this operation destroys the source! That should not change
      // its conflict set
      src_handle->remove("hello");
    }

    INFO(
      "Before the move commits, another operation changes the source, and "
      "commits");
    {
      auto interfere_tx = kv_store.create_tx();
      auto src_handle = interfere_tx.wo(source);
      src_handle->put("hello", "bob");
      REQUIRE(interfere_tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Moving operation should conflict on commit");
    REQUIRE(move_tx.commit() == ccf::kv::CommitResult::FAIL_CONFLICT);
  }
}

std::string rand_string(size_t i)
{
  return fmt::format("{}: {}", i, rand());
}

TEST_CASE("Mid-tx compaction")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  MapTypes::StringNum map_a("public:A");
  MapTypes::StringNum map_b("public:B");

  constexpr auto key_a = "a";
  constexpr auto key_b = "b";

  auto increment_vals = [&]() {
    auto tx = kv_store.create_tx();
    auto handle_a = tx.rw(map_a);
    auto handle_b = tx.rw(map_b);

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto new_val = a_opt.has_value() ? *a_opt + 1 : 0;

    handle_a->put(key_a, new_val);
    handle_b->put(key_b, new_val);

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  };

  increment_vals();

  {
    INFO("Compaction before get_handles");
    auto tx = kv_store.create_tx();

    increment_vals();
    kv_store.compact(kv_store.current_version());

    auto handle_a = tx.rw(map_a);
    auto handle_b = tx.rw(map_b);

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Compaction after get_handles");
    auto tx = kv_store.create_tx();

    auto handle_a = tx.rw(map_a);
    increment_vals();
    auto handle_b = tx.rw(map_b);
    kv_store.compact(kv_store.current_version());

    auto a_opt = handle_a->get(key_a);
    auto b_opt = handle_b->get(key_b);

    REQUIRE(a_opt == b_opt);

    const auto result = tx.commit();
    REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
  }

  {
    INFO("Compaction between get_handles");
    bool threw = false;

    try
    {
      auto tx = kv_store.create_tx();

      auto handle_a = tx.rw(map_a);
      // This transaction does something slow. Meanwhile...

      // ...another transaction commits...
      increment_vals();
      // ...and is compacted...
      kv_store.compact(kv_store.current_version());

      // ...then the original transaction proceeds, expecting to read a single
      // version
      // This should throw a CompactedVersionConflict error
      auto handle_b = tx.rw(map_b);

      auto a_opt = handle_a->get(key_a);
      auto b_opt = handle_b->get(key_b);

      REQUIRE(a_opt == b_opt);

      const auto result = tx.commit();
      REQUIRE(result == ccf::kv::CommitResult::SUCCESS);
    }
    catch (const ccf::kv::CompactedVersionConflict& e)
    {
      threw = true;
    }

    REQUIRE(threw);
    // In real operation, this transaction would be re-executed and hope to not
    // intersect a compaction
  }
}

TEST_CASE("Store clear")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  kv_store.initialise_term(42);

  auto map_a_name = "public:A";
  auto map_b_name = "public:B";
  MapTypes::StringNum map_a(map_a_name);
  MapTypes::StringNum map_b(map_b_name);

  INFO("Apply transactions and compact store");
  {
    size_t tx_count = 10;
    for (int i = 0; i < tx_count; i++)
    {
      auto tx = kv_store.create_tx();
      auto handle_a = tx.rw(map_a);
      auto handle_b = tx.rw(map_b);

      handle_a->put("key" + std::to_string(i), 42);
      handle_b->put("key" + std::to_string(i), 42);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    auto current_version = kv_store.current_version();
    kv_store.compact(current_version);

    REQUIRE(kv_store.get_map(current_version, map_a_name) != nullptr);
    REQUIRE(kv_store.get_map(current_version, map_b_name) != nullptr);

    REQUIRE(kv_store.current_version() != 0);
    REQUIRE(kv_store.compacted_version() != 0);
    auto tx_id = kv_store.current_txid();
    REQUIRE(tx_id.term != 0);
    REQUIRE(tx_id.version != 0);
  }

  INFO("Verify that store state is cleared");
  {
    kv_store.clear();
    auto current_version = kv_store.current_version();

    REQUIRE(kv_store.get_map(current_version, map_a_name) == nullptr);
    REQUIRE(kv_store.get_map(current_version, map_b_name) == nullptr);

    REQUIRE(kv_store.current_version() == 0);
    REQUIRE(kv_store.compacted_version() == 0);
    auto tx_id = kv_store.current_txid();
    REQUIRE(tx_id.term == 0);
    REQUIRE(tx_id.version == 0);
  }
}

TEST_CASE("Reported TxID after commit")
{
  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  kv_store.set_consensus(consensus);

  const auto map_name = "public:map";
  MapTypes::StringString map(map_name);
  auto store_last_seqno = kv_store.current_version();
  ccf::kv::Term initial_term = 2;
  ccf::kv::Term store_commit_term = initial_term;
  ccf::kv::Term store_read_term = 0;

  INFO("Initialise store");
  {
    kv_store.initialise_term(store_commit_term);

    for (store_last_seqno = kv_store.current_version(); store_last_seqno < 10;
         store_last_seqno++)
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      store_read_term = store_commit_term;
    }

    REQUIRE(kv_store.current_version() == store_last_seqno);
    REQUIRE_EQ(
      kv_store.current_txid(),
      ccf::kv::TxID(store_read_term, store_last_seqno));
  }

  INFO("Empty committed tx");
  {
    auto tx = kv_store.create_tx();

    // No map handle acquired

    // Tx is not yet committed
    REQUIRE_THROWS_AS(tx.get_txid(), std::logic_error);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // Committed transaction was not assigned a TxID because it was empty
    REQUIRE_FALSE(tx.get_txid().has_value());
  }

  INFO("Simple read-only tx");
  {
    // The ReadOnlyTx returned by store.create_read_only_tx() has no commit()
    // member. Here, we want to specifically test generic Txs that are created
    // by the CCF frontend, but do not write to the key-value store.
    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map); // Remember: opacity tx_id is acquired here

    // No need to read a key, acquiring a map handle is sufficient to acquire a
    // valid TxID

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    // Reported TxID includes store read term and last seqno
    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->term == store_read_term);
    REQUIRE(tx_id->version == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("Rollback while read-only tx is in progress");
  {
    auto tx = kv_store.create_tx();

    // Still a trivial case since the opacity TxID is acquired here
    auto handle = tx.ro(map);

    // Rollback at the current TxID, in the next term
    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->term == store_read_term); // Read in term in which
                                             // last entry was committed
    REQUIRE(tx_id->version == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("Read-only tx after rollback");
  {
    // Tricky! Rollback before opacity TxID is acquired

    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->term == store_read_term); // Read in term in which
                                             // last entry was committed
    REQUIRE(tx_id->version == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("More rollbacks");
  {
    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);
    kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->term == store_read_term);
    REQUIRE(tx_id->version == store_last_seqno);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }

  INFO("Commit tx in new term and no-op rollback");
  {
    {
      auto tx = kv_store.create_tx();
      auto handle = tx.rw(map);
      handle->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
      store_last_seqno = kv_store.current_version();
      store_read_term = store_commit_term;

      auto tx_id = tx.get_txid();
      REQUIRE(tx_id.has_value());
      REQUIRE(tx_id->term == store_commit_term);
      REQUIRE(tx_id->version == store_last_seqno);

      // Since a write Tx was committed, further Txs should read from there
    }

    {
      // Read-only tx should report the new term
      auto tx = kv_store.create_tx();
      auto handle = tx.ro(map);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      auto tx_id = tx.get_txid();
      REQUIRE(tx_id.has_value());
      REQUIRE(tx_id->term == store_read_term);
      REQUIRE(tx_id->version == store_last_seqno);
      REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
    }

    {
      kv_store.rollback(kv_store.current_txid(), ++store_commit_term);

      auto tx = kv_store.create_tx();
      auto handle = tx.ro(map);
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

      auto tx_id = tx.get_txid();
      REQUIRE(tx_id.has_value());
      REQUIRE(tx_id->term == store_read_term);
      REQUIRE(tx_id->version == store_last_seqno);
      REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
    }
  }

  INFO("Rollback to last entry in previous committed term");
  {
    // Rollback to initial term
    kv_store.rollback(
      {initial_term, store_last_seqno - 1}, ++store_commit_term);
    store_read_term = initial_term;

    auto tx = kv_store.create_tx();
    auto handle = tx.ro(map);
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);

    auto tx_id = tx.get_txid();
    REQUIRE(tx_id.has_value());
    REQUIRE(tx_id->term == store_read_term);
    REQUIRE(tx_id->version == store_last_seqno - 1);
    REQUIRE_EQ(tx_id.value(), kv_store.current_txid());
  }
}

template <typename T>
std::map<T, T> std_map_range(
  const std::map<T, T>& map, std::optional<T> from, std::optional<T> to)
{
  if (
    from.has_value() && to.has_value() &&
    (from.value() == to.value() || to.value() < from.value()))
  {
    return {};
  }

  auto f = map.begin();
  if (from.has_value())
  {
    f = map.lower_bound(from.value());
  }
  auto t = map.end();
  if (to.has_value())
  {
    t = map.lower_bound(to.value());
  }

  std::map<T, T> ret = {};
  for (auto it = f; it != t; it++)
  {
    ret.emplace(*it);
  }

  return ret;
}

template <typename T>
T get_map_get_factor(const std::map<T, T>& map, size_t factor)
{
  auto middle_it = map.begin();
  std::advance(middle_it, map.size() / factor);
  return middle_it->first;
}

template <class H, class T>
std::map<T, T> kv_map_range(H& h, std::optional<T> from, std::optional<T> to)
{
  std::map<T, T> range;
  auto f = [&range](const T& k, const T& v) { range.emplace(k, v); };
  h->range(f, from, to);
  return range;
}

TEST_CASE("Range")
{
  using KVMap = ccf::kv::untyped::Map;
  using KeyType = KVMap::K;
  using ValueType = KVMap::V;
  using RefMap = std::map<KeyType, ValueType>;
  using Serialiser = ccf::kv::serialisers::JsonSerialiser<size_t>;

  size_t size = 100;
  size_t entries_space_size = size * 10;
  const auto map_name = "public:map";
  const ValueType empty_value = {};

  ccf::kv::Store kv_store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  kv_store.set_encryptor(encryptor);
  RefMap ref;

  INFO("Populate map randomly");
  {
    std::random_device rand_dev;
    auto seed = rand_dev();
    LOG_INFO_FMT("Seed: {}", seed);
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> distrib(0, entries_space_size);

    auto tx = kv_store.create_tx();
    auto h = tx.rw<KVMap>(map_name);

    for (int i = 0; i < size; i++)
    {
      auto key = distrib(gen);
      auto serialised_key = Serialiser::to_serialised(key);
      h->put(serialised_key, empty_value);
      ref[serialised_key] = empty_value;
    }
    REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
  }

  INFO("Compare ranges between KV map and reference");
  {
    auto tx = kv_store.create_tx();
    auto h = tx.rw<KVMap>(map_name);

    // Test variety of ranges, with some expected to return nothing
    auto first = ref.begin()->first;
    auto last = ref.rbegin()->first;
    auto middle = get_map_get_factor(ref, 2);
    std::vector<std::pair<std::optional<KeyType>, std::optional<KeyType>>>
      ranges = {
        {first, first},
        {last, last},
        {last, first},
        {last, middle},
        {first, last},
        {first, middle},
        {middle, last},
        {first, last},
        {std::nullopt, first},
        {std::nullopt, middle},
        {std::nullopt, last},
        {first, std::nullopt},
        {middle, std::nullopt},
        {last, std::nullopt},
        {std::nullopt, std::nullopt}};

    for (const auto& range : ranges)
    {
      auto std_range = std_map_range(ref, range.first, range.second);
      auto kv_range = kv_map_range(h, range.first, range.second);
      REQUIRE(std_range == kv_range);
    }
  }

  auto key_to_remove = get_map_get_factor(ref, 2);

  INFO("Deleted keys are not returned");
  {
    INFO("Remove key");
    {
      auto tx = kv_store.create_tx();
      auto h = tx.rw<KVMap>(map_name);

      // Check key exists before deletion
      std::optional<KeyType> from = ref.begin()->first;
      std::optional<KeyType> to = ref.rbegin()->first;
      REQUIRE_NOTHROW(kv_map_range(h, from, to).at(key_to_remove));

      {
        h->remove(key_to_remove);
        REQUIRE(ref.erase(key_to_remove) == 1);
      }
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Range does not include key");
    {
      // Fresh tx/handle
      auto tx = kv_store.create_tx();
      auto h = tx.rw<KVMap>(map_name);

      std::optional<KeyType> from = ref.begin()->first;
      std::optional<KeyType> to = ref.rbegin()->first;
      auto kv_range = kv_map_range(h, from, to);
      REQUIRE_THROWS_AS(kv_range.at(key_to_remove), std::out_of_range);
    }
  }

  INFO("Return own writes too");
  {
    auto tx = kv_store.create_tx();
    auto h = tx.rw<KVMap>(map_name);

    INFO("Re-insert removed key");
    {
      REQUIRE(!h->get(key_to_remove).has_value());
      h->put(key_to_remove, empty_value);
      ref[key_to_remove] = empty_value;
      REQUIRE(h->get(key_to_remove).has_value());
    }

    ValueType well_known_value = {42};
    auto existing_key = get_map_get_factor(ref, 4);

    INFO("Modify existing key");
    {
      h->put(existing_key, well_known_value);
      ref[existing_key] = well_known_value;
    }

    // Do not commit transaction

    std::optional<KeyType> first = ref.begin()->first;
    std::optional<KeyType> last = ref.rbegin()->first;
    auto std_range = std_map_range(ref, first, last);
    auto kv_range = kv_map_range(h, first, last);
    REQUIRE(std_range == kv_range);
    REQUIRE(kv_range.at(existing_key) == well_known_value);
  }
}

TEST_CASE("Ledger entry chunk request")
{
  ccf::kv::Store store;
  auto encryptor = std::make_shared<ccf::kv::NullTxEncryptor>();
  auto consensus = std::make_shared<ccf::kv::test::StubConsensus>();
  store.set_encryptor(encryptor);
  store.set_consensus(consensus);

  ccf::Signatures signatures(ccf::Tables::SIGNATURES);
  ccf::SerialisedMerkleTree serialised_tree(
    ccf::Tables::SERIALISED_MERKLE_TREE);

  ccf::Nodes nodes(ccf::Tables::NODES);
  MapTypes::NumNum data("public:data");

  constexpr auto default_curve = ccf::crypto::CurveID::SECP384R1;
  auto kp = ccf::crypto::make_key_pair(default_curve);

  auto history = std::make_shared<ccf::NullTxHistory>(
    store, ccf::kv::test::PrimaryNodeId, *kp);
  store.set_history(history);

  auto chunker = std::make_shared<ccf::kv::LedgerChunker>();
  store.set_chunker(chunker);

  SUBCASE("Chunk at next signature")
  {
    // Ledger chunk flag is not set in the store
    REQUIRE(!store.should_create_ledger_chunk(store.current_version()));

    INFO("Add a transaction with the chunking flag enabled");
    {
      MapTypes::StringString map("public:map");
      auto tx = store.create_tx();

      // Request a ledger chunk at the next signature
      tx.set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);

      auto h1 = tx.rw(map);
      h1->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Flag is now set in the store
    REQUIRE(store.should_create_ledger_chunk(store.current_version()));

    INFO("Roll back the last transaction");
    {
      // Dummy rollback to the current TxID, which doesn't clear the chunking
      // flag
      store.rollback(store.current_txid(), store.commit_view());

      // Ledger chunk flag is still set in the store
      REQUIRE(store.should_create_ledger_chunk(store.current_version()));

      // Roll the last transaction back to clear the flag in the store
      store.rollback(
        {store.commit_view(), store.current_version() - 1},
        store.commit_view());

      // Ledger chunk flag is not set in the store anymore
      REQUIRE(!store.should_create_ledger_chunk(store.current_version()));
    }

    INFO("Add another transaction with the chunking flag enabled");
    {
      MapTypes::StringString map("public:map");
      auto tx = store.create_tx();

      // Request a ledger chunk at the next signature again
      tx.set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_AT_NEXT_SIGNATURE);

      auto h1 = tx.rw(map);
      h1->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    // Ledger chunk flag is now set in the store
    REQUIRE(store.should_create_ledger_chunk(store.current_version()));

    INFO(
      "Add a signature transaction which triggers chunk via entry header flag");
    {
      auto txid = store.next_txid();
      auto tx = store.create_reserved_tx(txid);
      auto sig_handle = tx.rw(signatures);
      auto tree_handle = tx.rw(serialised_tree);
      ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, txid.version);
      sig_handle->put(sigv);
      tree_handle->put({});
      auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
        tx.commit_reserved();
      auto& success = success_;
      auto& data = data_;
      REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(
        store.deserialize(data)->apply() ==
        ccf::kv::ApplyResult::PASS_SIGNATURE);

      // Header flag is set in the last entry
      const uint8_t* entry_data = data.data();
      size_t entry_data_size = data.size();
      auto header = serialized::peek<ccf::kv::SerialisedEntryHeader>(
        entry_data, entry_data_size);
      REQUIRE(
        (header.flags & ccf::kv::EntryFlags::FORCE_LEDGER_CHUNK_AFTER) != 0);
    }

    // Ledger chunk flag is not set in the store anymore
    chunker->produced_chunk_at(store.current_version());
    REQUIRE(!store.should_create_ledger_chunk(store.current_version()));
  }

  SUBCASE("Chunk before this transaction")
  {
    REQUIRE(!consensus->get_latest_data().has_value());

    INFO("Add a transaction with the chunking flag enabled");
    {
      MapTypes::StringString map("public:map");
      auto tx = store.create_tx();

      // Request a ledger chunk before tx
      tx.set_tx_flag(
        ccf::kv::CommittableTx::TxFlag::LEDGER_CHUNK_BEFORE_THIS_TX);

      auto h1 = tx.rw(map);
      h1->put("key", "value");
      REQUIRE(tx.commit() == ccf::kv::CommitResult::SUCCESS);
    }

    INFO("Verify that flag is included in serialised entry");
    {
      auto data_ = consensus->get_latest_data();
      REQUIRE(data_.has_value());
      auto& data = data_.value();

      const uint8_t* entry_data = data.data();
      size_t entry_data_size = data.size();
      auto header = serialized::peek<ccf::kv::SerialisedEntryHeader>(
        entry_data, entry_data_size);
      REQUIRE(
        (header.flags & ccf::kv::EntryFlags::FORCE_LEDGER_CHUNK_BEFORE) != 0);
    }
  }

  SUBCASE("Chunk when the snapshotter requires one")
  {
    store.set_flag(
      ccf::kv::AbstractStore::StoreFlag::SNAPSHOT_AT_NEXT_SIGNATURE);

    INFO("Add a signature that triggers a snapshot");
    {
      auto txid = store.next_txid();
      auto tx = store.create_reserved_tx(txid);

      // The store must know that we need a new ledger chunk at this version
      REQUIRE(store.should_create_ledger_chunk(txid.version));

      // Add the signature
      auto sig_handle = tx.rw(signatures);
      auto tree_handle = tx.rw(serialised_tree);
      ccf::PrimarySignature sigv(ccf::kv::test::PrimaryNodeId, txid.version);
      sig_handle->put(sigv);
      tree_handle->put({});
      auto [success_, data_, claims_digest, commit_evidence_digest, hooks] =
        tx.commit_reserved();
      auto& success = success_;
      auto& data = data_;
      REQUIRE(success == ccf::kv::CommitResult::SUCCESS);

      REQUIRE(
        store.deserialize(data)->apply() ==
        ccf::kv::ApplyResult::PASS_SIGNATURE);

      // Check that the ledger chunk header flag is set in the last entry
      const uint8_t* entry_data = data.data();
      size_t entry_data_size = data.size();
      auto header = serialized::peek<ccf::kv::SerialisedEntryHeader>(
        entry_data, entry_data_size);
      REQUIRE(
        (header.flags & ccf::kv::EntryFlags::FORCE_LEDGER_CHUNK_AFTER) != 0);
    }
  }
}

int main(int argc, char** argv)
{
  ccf::logger::config::default_init();
  ccf::crypto::openssl_sha256_init();
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  int res = context.run();
  ccf::crypto::openssl_sha256_shutdown();
  if (context.shouldExit())
    return res;
  return res;
}
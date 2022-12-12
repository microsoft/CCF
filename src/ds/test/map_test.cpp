// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/byte_vector.h"
#include "ccf/ds/logger.h"
#include "ccf/kv/serialisers/serialised_entry.h"
#include "ds/champ_map.h"
#include "ds/rb_map.h"
#include "ds/std_formatters.h"
#include "kv/untyped_change_set.h"

#include <doctest/doctest.h>
#include <random>
#include <unordered_map>

template <class K>
struct CollisionHash
{
  size_t operator()(const K& k) const noexcept
  {
    return std::hash<K>()(k) % 100;
  }
};

using K = kv::serialisers::SerialisedEntry;
using V = kv::serialisers::SerialisedEntry;

namespace map
{
  inline size_t get_size(uint64_t)
  {
    return sizeof(size_t);
  }
}

struct KVPair
{
  K k;
  V v;

  bool operator==(const KVPair&) const = default;
};

template <typename K>
using H = CollisionHash<K>;
// using H = std::hash<K>;

// Useful types
template <typename Key, typename Value>
using UntypedChampMap = champ::Map<Key, Value, H<Key>>;
using ChampMap = UntypedChampMap<K, V>;

template <typename Key, typename Value>
using UntypedRBMap = rb::Map<Key, Value>;
using RBMap = UntypedRBMap<K, V>;

class Model
{
  std::unordered_map<K, V> internal;

public:
  std::optional<V> get(const K& key) const
  {
    auto it = internal.find(key);
    if (it == internal.end())
      return {};

    return it->second;
  }

  Model put(const K& key, const V& value) const
  {
    auto next = *this;
    next.internal[key] = value;
    return next;
  }

  Model remove(const K& key) const
  {
    auto next = *this;
    next.internal.erase(key);
    return next;
  }
};

template <class M>
struct Op
{
  virtual ~Op() = default;
  virtual std::pair<const Model, const M> apply(const Model& a, const M& b) = 0;
  virtual std::string str() = 0;
};

template <class M>
struct Put : public Op<M>
{
  K k;
  V v;

  Put(K k_, V v_) : k(k_), v(v_) {}

  std::pair<const Model, const M> apply(const Model& a, const M& b)
  {
    return std::make_pair(a.put(k, v), b.put(k, v));
  }

  std::string str()
  {
    auto ss = std::stringstream();
    ss << "Put(" << H<K>()(k) << ", value of size " << v.size() << ")";
    return ss.str();
  }
};

template <class M>
struct Remove : public Op<M>
{
  K k;

  Remove(K k_) : k(k_) {}

  std::pair<const Model, const M> apply(const Model& a, const M& b)
  {
    return std::make_pair(a.remove(k), b.remove(k));
  }

  std::string str()
  {
    auto ss = std::stringstream();
    ss << "Remove(" << H<K>()(k) << ")";
    return ss.str();
  }
};

template <class M>
struct NoOp : public Op<M>
{
  NoOp() = default;

  std::pair<const Model, const M> apply(const Model& a, const M& b)
  {
    return std::make_pair(a, b);
  }

  std::string str()
  {
    auto ss = std::stringstream();
    ss << "NoOp (Remove not implemented!)";
    return ss.str();
  }
};

template <typename M>
std::vector<std::unique_ptr<Op<M>>> gen_ops(size_t n)
{
  std::random_device rand_dev;
  // auto seed = rand_dev();
  size_t seed = 3283898708;
  LOG_INFO_FMT("Seed: {}", seed);
  std::mt19937 gen(seed);
  std::uniform_int_distribution<> gen_op(0, 3);

  std::vector<std::unique_ptr<Op<M>>> ops;
  std::vector<K> keys;
  for (size_t i = 0; i < n; ++i)
  {
    V v(gen() % 128, 'x');
    std::unique_ptr<Op<M>> op;
    auto op_i = keys.empty() ? 0 : gen_op(gen);
    switch (op_i)
    {
      case 0:
      case 1: // insert
      {
        K k(gen() % 128, 'k');
        keys.push_back(k);
        op = std::make_unique<Put<M>>(k, v);

        break;
      }
      case 2: // update
      {
        std::uniform_int_distribution<> gen_idx(0, keys.size() - 1);
        auto k = keys[gen_idx(gen)];
        op = std::make_unique<Put<M>>(k, v);

        break;
      }
      case 3: // remove
      {
        // Remove operation is not yet implemented for RBMap
        if constexpr (std::is_same_v<M, ChampMap>)
        {
          std::uniform_int_distribution<> gen_idx(0, keys.size() - 1);
          auto i = gen_idx(gen);
          auto k = keys[i];
          keys.erase(keys.begin() + i);
          op = std::make_unique<Remove<M>>(k);
        }
        else
        {
          op = std::make_unique<NoOp<M>>();
        }
        break;
      }
      default:
        throw std::logic_error("bad op number");
    }
    ops.push_back(move(op));
  }

  return ops;
}

// TEST_CASE_TEMPLATE("Persistent map operations", M, RBMap, ChampMap)
// {
//   Model model;
//   M map;

//   auto ops = gen_ops<M>(500);
//   for (auto& op : ops)
//   {
//     LOG_DEBUG_FMT("{}", op->str());
//     auto r = op->apply(model, map);
//     auto model_new = r.first;
//     auto map_new = r.second;

//     INFO("check consistency of persistent maps");
//     {
//       size_t n = 0;
//       map_new.foreach([&](const auto& k, const auto& v) {
//         n++;
//         auto model_value = model_new.get(k);
//         REQUIRE(model_value.has_value());
//         REQUIRE(model_value.value() == v);
//         return true;
//       });
//       REQUIRE(n == map_new.size());
//     }

//     INFO("check persistence of previous versions");
//     {
//       size_t n = 0;
//       map.foreach([&](const auto& k, const auto& v) {
//         n++;
//         auto model_value = model.get(k);
//         REQUIRE(model_value.has_value());
//         REQUIRE(model_value.value() == v);
//         return true;
//       });
//       REQUIRE(n == map.size());
//     }

//     model = model_new;
//     map = map_new;
//   }
// }

TEST_CASE("Snapshot random")
{
  logger::config::default_init();

  Model model;
  ChampMap map;

  auto ops = gen_ops<ChampMap>(6);

  LOG_DEBUG_FMT(
    "Before: Map size: {}, serialised: {}",
    map.size(),
    map.get_serialized_size());

  for (auto& op : ops)
  {
    LOG_DEBUG_FMT("");
    LOG_DEBUG_FMT("-> {}", op->str());
    auto r = op->apply(model, map);

    map = r.second;
  }

  LOG_DEBUG_FMT(
    "After: Map size: {}, serialised: {}",
    map.size(),
    map.get_serialized_size());

  logger::config::loggers().clear();

  auto snapshot = map.make_snapshot();
  std::vector<uint8_t> s(map.get_serialized_size());
  snapshot->serialize(s.data());

  logger::config::default_init();

  LOG_DEBUG_FMT("Final snapshot size: {}: {}", s.size(), s);
}

template <class M>
static const M gen_map(size_t size)
{
  M map;
  for (size_t i = 0; i < size; ++i)
  {
    map = map.put(i, i);
  }
  return map;
}

// TEST_CASE_TEMPLATE("Snapshot map", M, RBMap, ChampMap)
// {
//   std::vector<KVPair> results;
//   uint32_t num_elements = 100;
//   auto map = gen_map<M>(num_elements);

//   INFO("Check initial content of map");
//   {
//     map.foreach([&results](const auto& key, const auto& value) {
//       results.push_back({key, value});
//       return true;
//     });
//     REQUIRE_EQ(num_elements, results.size());
//     REQUIRE_EQ(map.size(), num_elements);
//   }

//   INFO("Populate second map and compare");
//   {
//     std::set<K> keys;
//     M new_map;
//     for (const auto& p : results)
//     {
//       REQUIRE_LT(p.k, num_elements);
//       keys.insert(p.k);
//       new_map = new_map.put(p.k, p.v);
//     }
//     REQUIRE_EQ(num_elements, new_map.size());
//     REQUIRE_EQ(num_elements, keys.size());
//   }

//   INFO("Serialize map to array");
//   {
//     auto snapshot = map.make_snapshot();
//     std::vector<uint8_t> s(map.get_serialized_size());
//     snapshot->serialize(s.data());

//     auto new_map = map::deserialize_map<M>(s);

//     std::set<K> keys;
//     new_map.foreach([&keys](const auto& key, const auto& value) {
//       keys.insert(key);
//       REQUIRE_EQ(key, value);
//       return true;
//     });
//     REQUIRE_EQ(map.size(), new_map.size());
//     REQUIRE_EQ(map.size(), keys.size());

//     // Check that new entries can be added to deserialised map
//     uint32_t offset = 1000;
//     for (uint32_t i = offset; i < offset + num_elements; ++i)
//     {
//       new_map = new_map.put(i, i);
//     }
//     REQUIRE_EQ(new_map.size(), map.size() + num_elements);
//     for (uint32_t i = offset; i < offset + num_elements; ++i)
//     {
//       auto p = new_map.get(i);
//       REQUIRE(p.has_value());
//       REQUIRE(p.value() == i);
//     }
//   }

//   INFO("Ensure serialized state is byte identical");
//   {
//     auto snapshot_1 = map.make_snapshot();
//     std::vector<uint8_t> s_1(map.get_serialized_size());
//     snapshot_1->serialize(s_1.data());

//     auto snapshot_2 = map.make_snapshot();
//     std::vector<uint8_t> s_2(map.get_serialized_size());
//     snapshot_2->serialize(s_2.data());

//     REQUIRE_EQ(s_1, s_2);
//   }

//   INFO("Snapshot is immutable");
//   {
//     size_t current_size = map.size();
//     auto snapshot = map.make_snapshot();
//     std::vector<uint8_t> s_1(map.get_serialized_size());
//     snapshot->serialize(s_1.data());

//     // Add entry in map
//     auto key = current_size + 1;
//     REQUIRE(map.get(key) == std::nullopt);
//     map = map.put(key, key);

//     // Even though map has been updated, snapshot is not modified
//     std::vector<uint8_t> s_2(s_1.size());
//     snapshot->serialize(s_2.data());
//     REQUIRE_EQ(s_1, s_2);
//   }
// }

// using SerialisedKey = ccf::ByteVector;
// using SerialisedValue = ccf::ByteVector;

// TEST_CASE_TEMPLATE(
//   "Serialize map with different key sizes",
//   M,
//   UntypedChampMap<SerialisedKey, SerialisedValue>,
//   UntypedRBMap<SerialisedKey, SerialisedValue>)
// {
//   M map;
//   SerialisedKey key(16);
//   SerialisedValue long_key(128);
//   SerialisedValue value(8);
//   SerialisedValue long_value(256);

//   map = map.put(key, value);
//   map = map.put(long_key, long_value);

//   auto snapshot = map.make_snapshot();
//   std::vector<uint8_t> s(map.get_serialized_size());
//   snapshot->serialize(s.data());
// }

// template <typename M>
// std::map<K, V> get_all_entries(const M& map)
// {
//   std::map<K, V> entries;
//   map.foreach([&entries](const K& k, const V& v) {
//     REQUIRE(entries.find(k) == entries.end()); // assert for no duplicates
//     entries.insert({k, v});
//     return true;
//   });
//   return entries;
// }

// template <class S, class T>
// void verify_snapshot_compatibility(const S& source_map, T& target_map)
// {
//   auto source_entries = get_all_entries(source_map);
//   REQUIRE(source_entries.size() == source_map.size());

//   auto snapshot = source_map.make_snapshot();
//   std::vector<uint8_t> s(source_map.get_serialized_size());
//   snapshot->serialize(s.data());

//   target_map = map::deserialize_map<T>(s);
//   REQUIRE(target_map.size() == source_map.size());

//   auto target_entries = get_all_entries(target_map);
//   REQUIRE(target_entries.size() == target_map.size());
//   REQUIRE(source_entries == target_entries);
// }

// TEST_CASE("Snapshot compatibility")
// {
//   size_t size = 100;

//   INFO("CHAMP -> RB");
//   {
//     auto champ_map = gen_map<ChampMap>(size);
//     RBMap rb_map;
//     verify_snapshot_compatibility<ChampMap, RBMap>(champ_map, rb_map);
//   }

//   INFO("RB -> CHAMP");
//   {
//     auto rb_map = gen_map<RBMap>(size);
//     ChampMap champ_map;
//     verify_snapshot_compatibility<RBMap, ChampMap>(rb_map, champ_map);
//   }
// }

// template <typename M>
// void forall_threshold(const M& map, size_t threshold)
// {
//   size_t iterations_count = 0;
//   map.foreach([&iterations_count, threshold](const K& k, const V& v) {
//     iterations_count++;
//     if (iterations_count >= threshold)
//     {
//       return false;
//     }
//     return true;
//   });
//   REQUIRE(iterations_count == threshold);
// }

// TEST_CASE_TEMPLATE("Foreach", M, RBMap, ChampMap)
// {
//   size_t size = 100;
//   size_t threshold = size / 2;

//   auto map = gen_map<M>(size);
//   forall_threshold(map, threshold);
// }

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../champ_map.h"
#include "../rb_map.h"

#include <doctest/doctest.h>
#include <random>

using namespace std;

template <class K>
struct CollisionHash
{
  size_t operator()(const K& k) const noexcept
  {
    return std::hash<K>()(k) % 100;
  }
};

using K = uint64_t;
using V = uint64_t;

// using H = std::hash<K>;
using H = CollisionHash<K>;

struct Op
{
  virtual ~Op() = default;
  virtual pair<const RBMap<K, V>, const champ::Map<K, V, H>> apply(
    const RBMap<K, V>& a, const champ::Map<K, V, H>& b) = 0;
  virtual string str() = 0;
};

struct Put : public Op
{
  K k;
  V v;

  Put(K k_, V v_) : k(k_), v(v_) {}

  pair<const RBMap<K, V>, const champ::Map<K, V, H>> apply(
    const RBMap<K, V>& a, const champ::Map<K, V, H>& b)
  {
    return make_pair(a.put(k, v), b.put(k, v));
  }

  string str()
  {
    auto ss = stringstream();
    ss << "Put(" << H()(k) << ", " << v << ")";
    return ss.str();
  }
};

vector<unique_ptr<Op>> gen_ops(size_t n)
{
  random_device rand_dev;
  auto seed = rand_dev();
  mt19937 gen(seed);
  uniform_int_distribution<> gen_op(0, 2);

  vector<unique_ptr<Op>> ops;
  vector<K> keys;
  for (V v = 0; v < n; ++v)
  {
    unique_ptr<Op> op;
    auto op_i = ops.empty() ? 0 : gen_op(gen);
    switch (op_i)
    {
      case 0:
      case 1: // insert
      {
        auto k = gen();
        keys.push_back(k);
        op = make_unique<Put>(k, v);

        break;
      }
      case 2: // update
      {
        uniform_int_distribution<> gen_idx(0, keys.size() - 1);
        auto k = keys[gen_idx(gen)];
        op = make_unique<Put>(k, v);

        break;
      }
      default:
        throw logic_error("bad op number");
    }
    ops.push_back(move(op));
  }

  return ops;
}

TEST_CASE("persistent map operations")
{
  RBMap<K, V> rb;
  champ::Map<K, V, H> champ;

  auto ops = gen_ops(500);
  for (auto& op : ops)
  {
    auto r = op->apply(rb, champ);
    auto rb_new = r.first;
    auto champ_new = r.second;

    INFO("check consistency of persistent maps");
    {
      size_t n = 0;
      champ_new.foreach([&](const auto& k, const auto& v) {
        n++;
        auto p = rb_new.get(k);
        REQUIRE(p.has_value());
        REQUIRE(p.value() == v);
        return true;
      });
      REQUIRE(n == champ_new.size());
    }

    INFO("check persistence of previous versions");
    {
      size_t n = 0;
      champ.foreach([&](const auto& k, const auto& v) {
        n++;
        auto p = rb.get(k);
        REQUIRE(p.has_value());
        REQUIRE(p.value() == v);
        return true;
      });
      REQUIRE(n == champ.size());
    }

    rb = rb_new;
    champ = champ_new;
  }
}

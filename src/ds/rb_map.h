// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/map_serializers.h"

#include <cassert>
#include <memory>
#include <optional>

namespace rb
{
  template <class K, class V>
  class Snapshot;

  template <class K, class V>
  class Map
  {
  private:
    enum Color
    {
      R,
      B
    };

    struct Node
    {
      Node(
        Color c,
        const std::shared_ptr<const Node>& lft,
        const K& key,
        const V& val,
        const std::shared_ptr<const Node>& rgt) :
        _c(c),
        _lft(lft),
        _key(key),
        _val(val),
        _rgt(rgt)
      {
        total_size = 1;
        total_serialized_size = map::get_serialized_size_with_padding(key) +
          map::get_serialized_size_with_padding(val);
        if (lft)
        {
          total_size += lft->size();
          total_serialized_size += lft->serialized_size();
        }
        if (rgt)
        {
          total_size += rgt->size();
          total_serialized_size += rgt->serialized_size();
        }
      }

      Color _c;
      std::shared_ptr<const Node> _lft;
      K _key;
      V _val;
      std::shared_ptr<const Node> _rgt;
      size_t total_size = 0;
      size_t total_serialized_size = 0;

      size_t size() const
      {
        return total_size;
      }

      size_t serialized_size() const
      {
        return total_serialized_size;
      }
    };

    explicit Map(std::shared_ptr<const Node> const& node) : _root(node) {}

    Map(
      Color c,
      const Map& lft,
      const K& key,
      const V& val,
      const Map& rgt,
      std::optional<size_t> size = std::nullopt) :
      _root(std::make_shared<const Node>(c, lft._root, key, val, rgt._root))
    {
      assert(lft.empty() || lft.rootKey() < key);
      assert(rgt.empty() || key < rgt.rootKey());
    }

  public:
    using KeyType = K;
    using ValueType = V;
    using Snapshot = Snapshot<K, V>;

    Map() {}

    bool empty() const
    {
      return !_root;
    }

    size_t size() const
    {
      return empty() ? 0 : _root->size();
    }

    size_t get_serialized_size() const
    {
      return empty() ? 0 : _root->serialized_size();
    }

    std::optional<V> get(const K& key) const
    {
      auto v = getp(key);

      if (v)
        return *v;
      else
        return {};
    }

    const V* getp(const K& key) const
    {
      if (empty())
        return nullptr;

      auto& y = rootKey();

      if (key < y)
        return left().getp(key);
      else if (y < key)
        return right().getp(key);
      else
        return &rootValue();
    }

    Map put(const K& key, const V& value) const
    {
      Map t = insert(key, value);
      return Map(B, t.left(), t.rootKey(), t.rootValue(), t.right(), t.size());
    }

    Map remove(const K& key) const
    {
      throw std::logic_error("rb::Map::remove(k): Not implemented!");
    }

    template <class F>
    bool foreach(F&& f) const
    {
      if (!empty())
      {
        if (!left().foreach(std::forward<F>(f)))
        {
          return false;
        }
        if (!f(rootKey(), rootValue()))
        {
          return false;
        }
        if (!right().foreach(std::forward<F>(f)))
        {
          return false;
        }
      }
      return true;
    }

    std::unique_ptr<Snapshot> make_snapshot() const
    {
      return std::make_unique<Snapshot>(*this);
    }

  private:
    std::shared_ptr<const Node> _root;

    Color rootColor() const
    {
      return _root->_c;
    }

    const K& rootKey() const
    {
      return _root->_key;
    }

    const V& rootValue() const
    {
      return _root->_val;
    }

    Map left() const
    {
      return Map(_root->_lft);
    }

    Map right() const
    {
      return Map(_root->_rgt);
    }

    Map insert(const K& x, const V& v) const
    {
      if (empty())
        return Map(R, Map(), x, v, Map());

      const K& y = rootKey();
      const V& yv = rootValue();
      Color c = rootColor();

      if (rootColor() == B)
      {
        if (x < y)
          return balance(left().insert(x, v), y, yv, right());
        else if (y < x)
          return balance(left(), y, yv, right().insert(x, v));
        else
          return Map(c, left(), y, v, right());
      }
      else
      {
        if (x < y)
          return Map(c, left().insert(x, v), y, yv, right());
        else if (y < x)
          return Map(c, left(), y, yv, right().insert(x, v));
        else
          return Map(c, left(), y, v, right());
      }
    }

    // Called only when parent is black
    static Map balance(const Map& lft, const K& x, const V& v, const Map& rgt)
    {
      if (lft.doubledLeft())
        return Map(
          R,
          lft.left().paint(B),
          lft.rootKey(),
          lft.rootValue(),
          Map(B, lft.right(), x, v, rgt));
      else if (lft.doubledRight())
        return Map(
          R,
          Map(
            B, lft.left(), lft.rootKey(), lft.rootValue(), lft.right().left()),
          lft.right().rootKey(),
          lft.right().rootValue(),
          Map(B, lft.right().right(), x, v, rgt));
      else if (rgt.doubledLeft())
        return Map(
          R,
          Map(B, lft, x, v, rgt.left().left()),
          rgt.left().rootKey(),
          rgt.left().rootValue(),
          Map(
            B,
            rgt.left().right(),
            rgt.rootKey(),
            rgt.rootValue(),
            rgt.right()));
      else if (rgt.doubledRight())
        return Map(
          R,
          Map(B, lft, x, v, rgt.left()),
          rgt.rootKey(),
          rgt.rootValue(),
          rgt.right().paint(B));
      else
        return Map(B, lft, x, v, rgt);
    }

    bool doubledLeft() const
    {
      return !empty() && rootColor() == R && !left().empty() &&
        left().rootColor() == R;
    }

    bool doubledRight() const
    {
      return !empty() && rootColor() == R && !right().empty() &&
        right().rootColor() == R;
    }

    Map paint(Color c) const
    {
      return Map(c, left(), rootKey(), rootValue(), right());
    }
  };

  template <class K, class V>
  class Snapshot
  {
  private:
    const Map<K, V> map;

  public:
    Snapshot(const Map<K, V>& map_) : map(map_) {}

    size_t get_serialized_size()
    {
      return map.get_serialized_size();
    }

    void serialize(uint8_t* data)
    {
      size_t size = map.get_serialized_size();

      map.foreach([&data, &size](const K& k, const V& v) {
        // Serialize the key
        uint32_t key_size = map::serialize(k, data, size);
        map::add_padding(key_size, data, size);

        // Serialize the value
        uint32_t value_size = map::serialize(v, data, size);
        map::add_padding(value_size, data, size);
        return true;
      });

      CCF_ASSERT_FMT(size == 0, "buffer not filled, remaining:{}", size);
    }
  };
}

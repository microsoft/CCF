// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/map_serializers.h"

#include <cassert>
#include <memory>
#include <optional>
#include <stdexcept>

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
      return Map(
        B, t.left(), t.rootKey(), t.rootValue(), t.right(), t.size());
    }

    // Return a red-black tree without this key present.
    //
    // Based on the Introduction to Algorithms CLRS implementation.
    Map remove(const K& key) const
    {
      auto res = _remove(key);
      if (res.second && res.first.rootColor() == R)
      {
        auto r = res.first;
        res.first = Map(B, r.left(), r.rootKey(), r.rootValue(), r.right());
      }
      return res.first;
    }

    Map rotateRight() const
    {
      auto x = left();
      auto y = Map(rootColor(), x.right(), rootKey(), rootValue(), right());
      return Map(x.rootColor(), x.left(), x.rootKey(), x.rootValue(), y);
    }

    Map rotateLeft() const
    {
      auto y = right();
      auto x = Map(rootColor(), left(), rootKey(), rootValue(), y.left());
      return Map(y.rootColor(), x, y.rootKey(), y.rootValue(), y.right());
    }

    Map blacken() const
    {
      return Map(B, left(), rootKey(), rootValue(), right());
    }

    Map redden() const
    {
      return Map(R, left(), rootKey(), rootValue(), right());
    }

    // Fix a double black for this node, generated from removal.
    // The double black node is the left node of this one.
    // Return whether the double black needs to be propagated up.
    std::pair<Map, bool> fixDoubleBlackLeft() const
    {
      auto sibling = right();

      auto root = Map(*this);

      if (sibling.rootColor() == R)
      {
        // recolor root and sibling
        root = Map(
          R,
          root.left(),
          root.rootKey(),
          root.rootValue(),
          sibling.blacken());
        // rotate root left to make the sibling the root
        root = root.rotateLeft();
        // We've moved the double black node during the rotation so now we need
        // to fix it recursively
        auto fixedLeft = root.left().fixDoubleBlackLeft();
        root = Map(
          root.rootColor(),
          fixedLeft.first,
          root.rootKey(),
          root.rootValue(),
          root.right());
        if (!fixedLeft.second)
        {
          // nothing left to fix
          return std::make_pair(root, false);
        }
        // in fixing that we may have moved the double black to a child of this
        // root, so fix that now
        sibling = root.right();
      }

      auto doubleBlack = false;
      if (
        sibling.left().rootColor() == B &&
        sibling.right().rootColor() == B)
      {
        // current node is being made black, siblings children are both black so
        // we can safely convert the sibling to red and propagate the double
        // black
        sibling = sibling.redden();
        // we might still have to propagate the double black up
        doubleBlack = root.rootColor() == B;
        root =
          Map(B, root.left(), root.rootKey(), root.rootValue(), sibling);
      }
      else
      {
        if (sibling.right().rootColor() == B)
        {
          // root, sibling and sibling's right are all black
          // rotate the right with the sibling as the root
          auto siblingLeft = sibling.left().blacken();
          sibling = Map(
            R,
            siblingLeft,
            sibling.rootKey(),
            sibling.rootValue(),
            sibling.right());
          sibling = sibling.rotateRight();
          root = Map(
            root.rootColor(),
            root.left(),
            root.rootKey(),
            root.rootValue(),
            sibling);
        }

        auto recoloredSibling = Map(
          root.rootColor(),
          sibling.left(),
          sibling.rootKey(),
          sibling.rootValue(),
          sibling.right().blacken());
        root = Map(
          B,
          root.left(),
          root.rootKey(),
          root.rootValue(),
          recoloredSibling);
        root = root.rotateLeft();
        doubleBlack = false;
      }
      return std::make_pair(root, doubleBlack);
    }

    std::pair<Map, bool> fixDoubleBlackRight() const
    {
      auto sibling = left();

      auto root = Map(*this);

      if (sibling.rootColor() == R)
      {
        // recolor root and sibling
        root = Map(
          R,
          sibling.blacken(),
          root.rootKey(),
          root.rootValue(),
          root.right());
        // rotate root left to make the sibling the root
        root = root.rotateRight();
        // We've moved the double black node during the rotation so now we need
        // to fix it recursively
        auto fixedRight = root.right().fixDoubleBlackRight();
        root = Map(
          root.rootColor(),
          root.left(),
          root.rootKey(),
          root.rootValue(),
          fixedRight.first);
        if (!fixedRight.second)
        {
          // nothing left to fix
          return std::make_pair(root, false);
        }
        // in fixing that we may have moved the double black to a child of this
        // root, so fix that now
        sibling = root.left();
      }

      auto doubleBlack = false;
      if (
        sibling.left().rootColor() == B &&
        sibling.right().rootColor() == B)
      {
        // current node is being made black, siblings children are both black so
        // we can safely convert the sibling to red and propagate the double
        // black
        sibling = sibling.redden();
        // we might still have to propagate the double black up
        doubleBlack = root.rootColor() == B;
        root =
          Map(B, sibling, root.rootKey(), root.rootValue(), root.right());
      }
      else
      {
        if (sibling.left().rootColor() == B)
        {
          // root, sibling and sibling's left are all black
          // rotate the right with the sibling as the root
          auto siblingRight = sibling.right().blacken();
          sibling = Map(
            R,
            sibling.left(),
            sibling.rootKey(),
            sibling.rootValue(),
            siblingRight);
          sibling = sibling.rotateLeft();
          root = Map(
            root.rootColor(),
            sibling,
            root.rootKey(),
            root.rootValue(),
            root.right());
        }

        auto recoloredSibling = Map(
          root.rootColor(),
          sibling.left().blacken(),
          sibling.rootKey(),
          sibling.rootValue(),
          sibling.right());
        root = Map(
          B,
          recoloredSibling,
          root.rootKey(),
          root.rootValue(),
          root.right());
        root = root.rotateRight();
        doubleBlack = false;
      }
      return std::make_pair(root, doubleBlack);
    }

    // Remove the node with the given key.
    // returns a new map along with a bool indicating whether we need to handle
    // a double black.
    std::pair<Map, bool> _remove(const K& key) const
    {
      if (empty())
      {
        // key not present in the tree, can't remove it so just return an empty
        // map.
        return std::make_pair(Map(), false);
      }

      auto& rootk = rootKey();

      if (key < rootk)
      {
        // remove key from the left subtree
        auto left_without = left()._remove(key);
        // copy the left into a new map to return
        auto newMap =
          Map(rootColor(), left_without.first, rootKey(), rootValue(), right());
        if (left_without.second)
        {
          // there is a double black node in the left subtree so fix it up
          return newMap.fixDoubleBlackLeft();
        }
        // no double blacks are present
        return std::make_pair(newMap, false);
      }
      else if (rootk < key)
      {
        // mirror of the above case
        auto right_without = right()._remove(key);
        auto newMap =
          Map(rootColor(), left(), rootKey(), rootValue(), right_without.first);
        if (right_without.second)
        {
          return newMap.fixDoubleBlackRight();
        }
        return std::make_pair(newMap, false);
      }
      else if (key == rootk)
      {
        // delete key from this node
        if (left().empty() && right().empty())
        {
          // leaf node, a simple case
          auto doubleBlack = rootColor() == B;
          return std::make_pair(Map(), doubleBlack);
        }
        else if (left().empty())
        {
          // nothing on the left so we can replace this node with the right
          // child
          auto r = right();
          // Exactly one of the node being removed and the right node are black:
          // - the left is empty so has a black height of 1
          // - the right must also have a black height of 1 to maintain the
          // height but it is not empty or we would have hit the above if
          // statement
          // - therefore the right node is red.
          assert(r.left().empty());
          assert(r.right().empty());
          assert(r.rootColor() == Red);
          return std::make_pair(r.blacken(), false);
        }
        else if (right().empty())
        {
          // mirror of the above case
          return std::make_pair(left().blacken(), false);
        }
        else
        {
          // both children are non-empty, swap this node's key and value with
          // the successor and then delete the successor
          auto successor = right().minimum();
          auto right_without = right()._remove(successor.first);
          auto newMap = Map(
            rootColor(),
            left(),
            successor.first,
            successor.second,
            right_without.first);
          if (right_without.second)
          {
            return newMap.fixDoubleBlackRight();
          }
          return std::make_pair(newMap, false);
        }
      }
      else
      {
        // key not found in the tree
        return std::make_pair(Map(*this), false);
      }
    }

    // Return the minimum key in this map along with its value.
    std::pair<K, V> minimum() const
    {
      assert(!empty());

      if (left().empty())
      {
        return std::make_pair(rootKey(), rootValue());
      }
      else
      {
        return left().minimum();
      }
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
      if (empty())
      {
        // empty nodes are black
        return B;
      }
      else
      {
        return _root->_c;
      }
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

    // Insert a new key and value pair.
    Map insert(const K& k, const V& v) const
    {
      if (empty())
        return Map(R, Map(), k, v, Map());

      const K& rootk = rootKey();
      const V& rooty = rootValue();
      Color rootc = rootColor();

      if (rootc == B)
      {
        if (k < rootk)
          return balance(left().insert(k, v), rootk, rooty, right());
        else if (rootk < k)
          return balance(left(), rootk, rooty, right().insert(k, v));
        else
          return Map(rootc, left(), rootk, v, right());
      }
      else
      {
        if (k < rootk)
          return Map(rootc, left().insert(k, v), rootk, rooty, right());
        else if (rootk < k)
          return Map(rootc, left(), rootk, rooty, right().insert(k, v));
        else
          return Map(rootc, left(), rootk, v, right());
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
            B,
            lft.left(),
            lft.rootKey(),
            lft.rootValue(),
            lft.right().left()),
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

    // Check properties of the tree
    void check() const
    {
      int totalBlackCount;
      _check(0, totalBlackCount);
    }

    // Print an s-expression style representation of the tree's colors
    void print() const
    {
      if (empty())
      {
        std::cout << "B";
        return;
      }
      std::cout << "(";
      std::cout << (rootColor() == B ? "B" : "R") << " ";
      left().print();
      right().print();
      std::cout << ")";
    }

    void _check(int blackCount, int& totalBlackCount) const
    {
      if (empty())
      {
        totalBlackCount = blackCount + 1;
        return;
      }

      if (rootColor() == R)
      {
        if (!left().empty() && left().rootColor() == R)
        {
          throw std::logic_error("rb::Map::check(): Double red node found");
        }
        if (!right().empty() && right().rootColor() == R)
        {
          throw std::logic_error("rb::Map::check(): Double red node found");
        }
      }
      int leftBlackCount = 0;
      int rightBlackCount = 0;
      left()._check(
        blackCount + (rootColor() == B ? 1 : 0), leftBlackCount);
      right()._check(
        blackCount + (rootColor() == B ? 1 : 0), rightBlackCount);

      if (leftBlackCount != rightBlackCount)
      {
        print();
        std::cout << std::endl;
        throw std::logic_error(fmt::format(
          "rb::Map::check(): black counts didn't match between left and right "
          "{} {}",
          leftBlackCount,
          rightBlackCount));
      }

      totalBlackCount = leftBlackCount + (rootColor() == B ? 1 : 0);
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

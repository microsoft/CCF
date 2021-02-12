// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <cassert>
#include <memory>
#include <optional>

template <class K, class V>
class RBMap
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
    {}

    Color _c;
    std::shared_ptr<const Node> _lft;
    K _key;
    V _val;
    std::shared_ptr<const Node> _rgt;
  };

  explicit RBMap(std::shared_ptr<const Node> const& node) : _root(node) {}

  RBMap(
    Color c, const RBMap& lft, const K& key, const V& val, const RBMap& rgt) :
    _root(std::make_shared<const Node>(c, lft._root, key, val, rgt._root))
  {
    assert(lft.empty() || lft.rootKey() < key);
    assert(rgt.empty() || key < rgt.rootKey());
  }

public:
  RBMap() {}

  bool empty() const
  {
    return !_root;
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

  RBMap put(const K& key, const V& value) const
  {
    RBMap t = insert(key, value);
    return RBMap(B, t.left(), t.rootKey(), t.rootValue(), t.right());
  }

  template <class F>
  void foreach(F&& f) const
  {
    if (!empty())
    {
      left().foreach(std::forward<F>(f));
      f(rootKey(), rootValue());
      right().foreach(std::forward<F>(f));
    }
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

  RBMap left() const
  {
    return RBMap(_root->_lft);
  }

  RBMap right() const
  {
    return RBMap(_root->_rgt);
  }

  RBMap insert(const K& x, const V& v) const
  {
    if (empty())
      return RBMap(R, RBMap(), x, v, RBMap());

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
        return RBMap(c, left(), y, v, right());
    }
    else
    {
      if (x < y)
        return RBMap(c, left().insert(x, v), y, yv, right());
      else if (y < x)
        return RBMap(c, left(), y, yv, right().insert(x, v));
      else
        return RBMap(c, left(), y, v, right());
    }
  }

  // Called only when parent is black
  static RBMap balance(
    const RBMap& lft, const K& x, const V& v, const RBMap& rgt)
  {
    if (lft.doubledLeft())
      return RBMap(
        R,
        lft.left().paint(B),
        lft.rootKey(),
        lft.rootValue(),
        RBMap(B, lft.right(), x, v, rgt));
    else if (lft.doubledRight())
      return RBMap(
        R,
        RBMap(
          B, lft.left(), lft.rootKey(), lft.rootValue(), lft.right().left()),
        lft.right().rootKey(),
        lft.right().rootValue(),
        RBMap(B, lft.right().right(), x, v, rgt));
    else if (rgt.doubledLeft())
      return RBMap(
        R,
        RBMap(B, lft, x, v, rgt.left().left()),
        rgt.left().rootKey(),
        rgt.left().rootValue(),
        RBMap(
          B, rgt.left().right(), rgt.rootKey(), rgt.rootValue(), rgt.right()));
    else if (rgt.doubledRight())
      return RBMap(
        R,
        RBMap(B, lft, x, v, rgt.left()),
        rgt.rootKey(),
        rgt.rootValue(),
        rgt.right().paint(B));
    else
      return RBMap(B, lft, x, v, rgt);
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

  RBMap paint(Color c) const
  {
    return RBMap(c, left(), rootKey(), rootValue(), right());
  }
};

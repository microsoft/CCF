#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <cmath>

#include <memory>
#include <list>
#include <vector>
#include <stack>
#include <sstream>
#include <functional>


#ifdef WIN32
#include <stdlib.h>
#if BYTE_ORDER == LITTLE_ENDIAN
  #define htobe32(X) _byteswap_ulong(X)
  #define be32toh(X) _byteswap_ulong(X)
#else
  #define htobe32(X) (X)
  #define be32toh(X) (X)
#endif
#undef max
#endif


// All british.
// Documentation strings.

#define TRACE_ENABLED false
#define TRACE_HASH_SIZE 3
#define TRACE(X) if (TRACE_ENABLED) { X; std::cout.flush(); };

#if TRACE_ENABLED
#include <iostream>
#endif

namespace Merkle
{
  template<size_t SIZE>
  struct HashT {
    uint8_t bytes[SIZE];

    HashT<SIZE>() {
      std::fill(bytes, bytes + SIZE, 0);
    }

    HashT<SIZE>(const uint8_t *bytes) {
      std::copy(bytes, bytes + SIZE, this->bytes);
    }

    HashT<SIZE>(const std::string &s) {
      if (s.length() != 2*SIZE)
        throw std::runtime_error("invalid hash string");
      for (size_t i=0; i < SIZE; i++) {
        int tmp;
        sscanf(s.c_str()+2*i, "%02x", &tmp);
        bytes[i] = tmp;
      }
    }

    std::string to_string(size_t num_bytes = SIZE) const {
      static char buf[3];
      size_t num_chars = 2 * num_bytes;
      std::string r(num_chars, '_');
      for (size_t i = 0; i < num_bytes; i++)
        snprintf(r.data() + 2*i, num_chars + 1 - 2*i, "%02X", bytes[i]);
      return r;
    }

    HashT<SIZE> operator=(const HashT<SIZE> &other) {
      std::copy(other.bytes, other.bytes + SIZE, bytes);
      return *this;
    }

    bool operator==(const HashT<SIZE> &other) const {
      return memcmp(bytes, other.bytes, SIZE) == 0;
    }

    bool operator!=(const HashT<SIZE> &other) const {
      return memcmp(bytes, other.bytes, SIZE) != 0;
    }
  };

  template<
    size_t HASH_SIZE,
    void (*HASH_FUNCTION)(const HashT<HASH_SIZE> &l, const HashT<HASH_SIZE> &r, HashT<HASH_SIZE> &out)>
  class PathT {
  public:
    typedef enum { PATH_LEFT, PATH_RIGHT } Direction;

    typedef struct {
      HashT<HASH_SIZE> hash; // This is a copy; do we want a shared_ptr<HashT>?
      Direction direction;
    } Element;

    PathT(const HashT<HASH_SIZE> &leaf, std::list<Element> &&elements)
      : leaf(leaf), elements(elements)
    {}
    PathT(const PathT &other) {
      leaf = other.leaf;
      elements = other.elements;
    }
    PathT(PathT &&other) {
      leaf = std::move(other.leaf);
      elements = std::move(other.elements);
    }
    PathT(std::vector<uint8_t> &bytes) {
      throw std::runtime_error("not implemented yet");
    }

    bool verify(const HashT<HASH_SIZE> &root) const {
      HashT<HASH_SIZE> result = leaf, tmp;
      TRACE(std::cout << "> verify " << leaf.to_string(TRACE_HASH_SIZE) << std::endl);
      for (const Element &e : elements) {
        if (e.direction == PATH_LEFT) {
          TRACE(std::cout << " - " << e.hash.to_string(TRACE_HASH_SIZE) << " x " << result.to_string(TRACE_HASH_SIZE) << std::endl);
          HASH_FUNCTION(e.hash, result, tmp);
        }
        else {
          TRACE(std::cout << " - " << result.to_string(TRACE_HASH_SIZE) << " x " << e.hash.to_string(TRACE_HASH_SIZE) << std::endl);
          HASH_FUNCTION(result, e.hash, tmp);
        }
        std::swap(result, tmp);
      }
      TRACE(std::cout << " = " << result.to_string(TRACE_HASH_SIZE) << std::endl);
      return result == root;
    }

    std::vector<uint8_t> serialise() const {
      throw std::runtime_error("not implemented yet");
    }

    operator std::vector<uint8_t>() const {
      return serialise();
    }

    static void deserialise(std::vector<uint8_t> &bytes) {
      throw std::runtime_error("not implemented yet");
    }

    size_t size() const { return elements.size(); }

    const HashT<HASH_SIZE>& operator[](size_t i) const { return *elements[i].hash; }

    typedef typename std::list<Element>::const_iterator const_iterator;
    const_iterator begin() { return elements.begin(); }
    const_iterator end() { return elements.end(); }

    std::string to_string(size_t num_bytes = HASH_SIZE) const {
      std::stringstream stream;
      stream << leaf.to_string(num_bytes);
      for (auto &e : elements)
        stream << " " << e.hash.to_string(num_bytes) << (e.direction == PATH_LEFT ? "(L)" : "(R)");
      return stream.str();
    }

  protected:
    HashT<HASH_SIZE> leaf;
    std::list<Element> elements;
  };


  template<
    size_t HASH_SIZE,
    void (*HASH_FUNCTION)(const HashT<HASH_SIZE> &l, const HashT<HASH_SIZE> &r, HashT<HASH_SIZE> &out)>
  class TreeT {
  protected:
    struct Node {
      static Node* make(const HashT<HASH_SIZE> &hash)
      {
        auto r = new Node();
        r->left = r->right = nullptr;
        r->hash = hash;
        r->size = r->height = 1;
        r->dirty = false;
        assert(r->invariant());
        return r;
      }

      static Node* make(Node *left, Node *right)
      {
        assert(left && right);
        auto r = new Node();
        r->left = left;
        r->right = right;
        r->dirty = true;
        r->size = left->size + right->size + 1;
        r->height = std::max(left->height, right->height) + 1;
        r->left->parent = r->right->parent = r;
        assert(r->invariant());
        return r;
      }

      bool invariant() {
        bool c1 = (!parent || parent->left == this || parent->right == this);
        bool c2 = (left && right) || (!left && !right);
        bool cl = !left || left->invariant();
        bool cr = !right || right->invariant();
        return c1 && c2 && cl && cr;
      }

      ~Node() {
        assert(invariant());
        parent = nullptr;
        delete(left);
        delete(right);
      }

      bool is_full() const {
        size_t max_size =  (1 << height) - 1;
        assert(size <= max_size);
        return size == max_size;
      }

      HashT<HASH_SIZE> hash;
      Node *parent;
      Node *left, *right;
      size_t size, height;
      bool dirty;
    };

  public:
    TreeT() {}
    TreeT(const TreeT &other)
      : leaf_nodes(other.leaf_nodes),
        _root(other._root)
    {}
    TreeT(TreeT &&other)
      : leaf_nodes(std::move(other.leaf_nodes)),
        _root(std::move(other._root))
    {}
    ~TreeT() {
      delete(_root);
      for (auto n : new_leaf_nodes)
        delete(n);
    }

    TreeT(std::vector<uint8_t> &bytes) {
      throw std::runtime_error("not implemented yet");
    }

    typedef HashT<HASH_SIZE> Hash;
    typedef PathT<HASH_SIZE, HASH_FUNCTION> Path;
    typedef TreeT<HASH_SIZE, HASH_FUNCTION> Tree;

    void insert(const Hash &hash) {
      TRACE(std::cout << "> insert " << hash.to_string(TRACE_HASH_SIZE) << std::endl;);
      new_leaf_nodes.push_back(Node::make(hash));
      statistics.num_insert++;
    }

    void insert(const std::vector<Hash> &hashes) {
      for (auto hash : hashes)
        insert(hash);
    }

    void insert(const std::list<Hash> &hashes) {
      for (auto hash : hashes)
        insert(hash);
    }

    void flush_to(size_t index) {
      TRACE(std::cout << "> flush_to " << index << std::endl;);
      statistics.num_flush++;

      if (index < min_index())
        return;

      if (index > max_index())
        throw std::runtime_error("leaf index out of bounds");

      if (index >= num_flushed + leaf_nodes.size())
        insert_new_leaves(true);

      assert(index < _root->size);

      Node *final = walk_to(index, [this](Node *&n, bool go_right) {
        if (go_right && n->left) {
          TRACE(std::cout << " - conflate " << n->left->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
          if (n->left && n->left->dirty)
            hash(n->left);
          delete(n->left->left);
          n->left->left = nullptr;
          delete(n->left->right);
          n->left->right = nullptr;
        }
        return true;
      });

      size_t num_newly_flushed = index - num_flushed;
      leaf_nodes.erase(leaf_nodes.begin(), leaf_nodes.begin() + num_newly_flushed);
      num_flushed += num_newly_flushed;
    }

    void retract_to(size_t index) {
      TRACE(std::cout << "> retract_to " << index << std::endl;);
      statistics.num_retract++;

      if (index > max_index())
        return;

      if (index < min_index())
        throw std::runtime_error("leaf index out of bounds");

      if (index >= num_flushed + leaf_nodes.size()) {
        size_t over = index - (num_flushed + leaf_nodes.size()) + 1;
        while (new_leaf_nodes.size() > over) {
          delete(new_leaf_nodes.back());
          new_leaf_nodes.pop_back();
        }
        return;
      }

      insert_new_leaves(true);

      assert(_root && index < _root->size);

      Node *final = walk_to(index, [this](Node *&n, bool go_right) {
        bool go_left = !go_right;
        n->dirty = true;
        if (go_left && n->right) {
          TRACE(std::cout << " - eliminate " << n->right->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
          bool is_root = n == _root;

          Node *old_parent = n->parent;
          Node *old_left = n->left;
          delete(n->right);
          n->right = nullptr;

          *n = *old_left;
          n->parent = old_parent;

          old_left->left = old_left->right = nullptr;
          old_left->parent = nullptr;
          delete(old_left);
          old_left = nullptr;

          if (n->left && n->right) {
            n->left->parent = n;
            n->right->parent = n;
            n->dirty = true;
          }

          if (n->parent) {
            Node *parent = n->parent;

            while (parent) {
              size_t &parent_size = parent->size;
              parent_size = 1;
              parent_size += parent->left->size;
              parent_size += parent->right->size;

              parent->height = std::max(parent->left->height, parent->right->height) + 1;

              parent = parent->parent;
            }
          }
          else if (is_root) {
            TRACE(std::cout << " - new root: " << n->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
            assert(n->parent == nullptr);
            assert(_root == n);
          }

          assert(n->invariant());

          TRACE(std::cout << " - after elimination: " << std::endl << to_string(TRACE_HASH_SIZE) << std::endl;);
          return false;
        }
        else
          return true;
      });

      // The leaf is now elsewhere, save the pointer.
      leaf_nodes[index-num_flushed] = final;

      size_t num_retracted = num_leaves() - index - 1;
      if (num_retracted < leaf_nodes.size())
        leaf_nodes.resize(leaf_nodes.size() - num_retracted);
      else
        leaf_nodes.clear();

      assert(num_leaves() == index + 1);
    }

    const Tree split(size_t index) {
      throw std::runtime_error("not implemented yet");
    }

    const Hash& root() {
      TRACE(std::cout << "> root" << std::endl;);
      statistics.num_root++;
      compute_root();
      assert(_root && !_root->dirty);
      TRACE(std::cout << " - root: " << _root->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
      return _root->hash;
    }

    std::unique_ptr<const Hash> past_root(size_t index) const {
      throw std::runtime_error("not implemented yet");
    }

    Node* walk_to(size_t index, std::function<bool(Node*&, bool)> f)
    {
      Node *cur = _root;
      size_t it = index << (sizeof(_root->height)*8 - _root->height + 1);

      for (size_t height = _root->height; height > 1; ) {
        assert(cur->invariant());
        bool go_right = (it >> (8*sizeof(it)-1)) & 0x01;
        TRACE(std::cout << " - at " << cur->hash.to_string(TRACE_HASH_SIZE)
                        << " (" << cur->size << "/" << cur->height << ")"
                        << " (" << (go_right ? "R" : "L") << ")" << std::endl;);
        if (cur->height == height) {
          if (!f(cur, go_right))
            continue;
          cur = (go_right ? cur->right : cur->left);
        }
        it <<= 1;
        height--;
      }

      return cur;
    }

    std::unique_ptr<Path> path(size_t index) {
      TRACE(std::cout << "> path from " << index << std::endl;);

      if (index < num_flushed || index >= num_leaves())
        throw std::runtime_error("invalid leaf index");

      compute_root();

      assert(index < _root->size);

      std::list<typename Path::Element> elements;

      Node *final = walk_to(index, [&elements](Node *n, bool go_right) {
          typename Path::Element e;
          e.hash = go_right ? n->left->hash : n->right->hash;
          e.direction = go_right ? Path::PATH_LEFT : Path::PATH_RIGHT;
          elements.push_front(std::move(e));
          return true;
      });

      auto leaf = leaf_node(index);
      if (final != leaf)
        throw std::runtime_error("BUG: path extraction failed");

      return std::make_unique<Path>(leaf->hash, std::move(elements));
    }

    std::vector<uint8_t> serialise() const {
      throw std::runtime_error("not implemented yet");
    }

    operator std::vector<uint8_t>() const {
      return serialise();
    }

    static Tree* deserialise(std::vector<uint8_t> &bytes) {
      throw std::runtime_error("not implemented yet");
    }

    const Hash& operator[](size_t index) const {
      return leaf(index);
    }

    const Hash& leaf(size_t index) const {
      if (index >= num_leaves())
        throw std::runtime_error("leaf index out of bounds");
      return leaf_nodes[index-num_flushed];
    }

    const Node* leaf_node(size_t index) const {
      if (index >= num_leaves())
        throw std::runtime_error("leaf index out of bounds");
      return leaf_nodes[index-num_flushed];
    }

    size_t num_nodes() const {
      return (_root ? _root->size : 0) + new_leaf_nodes.size();
    }

    size_t num_leaves() const {
      return num_flushed + leaf_nodes.size() + new_leaf_nodes.size();
    }

    size_t max_index() const {
      return num_leaves() - 1;
    }

    size_t min_index() const {
      return num_flushed;
    }

    size_t size() const {
      // size in bytes for serialisation?
      throw std::runtime_error("not implemented yet");
    }

    struct Statistics {
      size_t num_insert = 0, num_hash = 0, num_root = 0;
      size_t num_flush = 0, num_retract = 0;

      std::string to_string() const {
        std::stringstream stream;
        stream << "num_insert=" << num_insert
               << " num_hash=" << num_hash
               << " num_root=" << num_root
               << " num_retract=" << num_retract
               << " num_flush=" << num_flush;
        return stream.str();
      }
    } statistics;

    std::string to_string(size_t num_bytes = HASH_SIZE) {
      static const std::string dirty_hash(2*num_bytes, '?');
      std::stringstream stream;
      std::vector<Node*> level, next_level;
      Node *previous = nullptr;

      if (num_leaves() == 0) {
        stream << "<EMPTY>" << std::endl;
        return stream.str();
      }

      // compute_root();
      // insert_new_leaves();

      if (!_root) {
        stream << "No root." << std::endl;
      }
      else {
        size_t level_no = 0;
        level.push_back(_root);
        while (!level.empty()) {
          stream << level_no++ << ": ";
          for (auto n : level) {
            // std::cout << "* " << n->hash.to_string(num_bytes) << std::endl;
            assert(n->invariant());
            stream << (n->dirty ? dirty_hash : n->hash.to_string(num_bytes));
            stream << "(" << n->size << "," << n->height << ")";
            if (n->left) next_level.push_back(n->left);
            if (n->right) next_level.push_back(n->right);
            stream << " ";
          }
          stream << std::endl << std::flush;
          std::swap(level, next_level);
          next_level.clear();
        }
      }

      stream << "+: new leaves=" << new_leaf_nodes.size() << ", num_flushed=" << num_flushed << std::endl;
      stream << "S: " << statistics.to_string() << std::endl;

      return stream.str();
    }

  protected:
    std::vector<Node*> leaf_nodes;
    std::vector<Node*> new_leaf_nodes;
    Node *_root = nullptr;
    typedef struct { Node *n; bool left; } InsertionStackElement;
    std::vector<InsertionStackElement> insertion_stack;
    std::vector<Node*> hashing_stack;
    size_t num_flushed = 0;

    void hash(Node *n, size_t indent=2)
    {
      assert(hashing_stack.empty());
      hashing_stack.reserve(n->height);
      hashing_stack.push_back(n);

      while (!hashing_stack.empty()) {
        n = hashing_stack.back();
        assert((n->left && n->right) || (!n->left && !n->right));

        if (n->left && n->left->dirty)
          hashing_stack.push_back(n->left);
        else if (n->right && n->right->dirty)
          hashing_stack.push_back(n->right);
        else
        {
          assert (n->left && n->right);
          HASH_FUNCTION(n->left->hash, n->right->hash, n->hash);
          statistics.num_hash++;
          TRACE(std::cout << std::string(indent, ' ') << "+ h("
                          << n->left->hash.to_string(TRACE_HASH_SIZE) << ", "
                          << n->right->hash.to_string(TRACE_HASH_SIZE) << ") == "
                          << n->hash.to_string(TRACE_HASH_SIZE) << std::endl);
          n->dirty = false;
          hashing_stack.pop_back();
        }
      }
    }

    void compute_root() {
      insert_new_leaves();
      if (!insertion_stack.empty())
        _root = process_insertion_stack();
      assert(_root->parent == nullptr);
      if (!_root || _root->dirty) {
        if (num_leaves() == 0)
          throw std::runtime_error("empty tree does not have a root");
        hash(_root);
        assert(_root && !_root->dirty);
      }
    }

    void insert_new_leaf_recursive(Node *&n, Node *new_leaf) {
      if (!n)
        n = new_leaf;
      else {
        if (n->is_full()) {
          Node *p = n->parent;
          n = Node::make(n, new_leaf);
          n->parent = p;
        }
        else {
          TRACE(std::cout << " @ " << n->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
          assert(n->left && n->right);
          if (!n->left->is_full())
            insert_new_leaf_recursive(n->left, new_leaf);
          else
            insert_new_leaf_recursive(n->right, new_leaf);
          n->dirty = true;
          n->size = n->left->size + n->right->size + 1;
          n->height = std::max(n->left->height, n->right->height) + 1;
        }
      }
    }

    void continue_insertion_stack(Node *n, Node *new_leaf) {
      while (true)
      {
        TRACE(std::cout << "  @ " << n->hash.to_string(TRACE_HASH_SIZE) << std::endl;);

        if (n->is_full()) {
          Node *result = Node::make(n, new_leaf);
          assert(!insertion_stack.empty() || result->parent == nullptr);
          if (!insertion_stack.empty())
            result->parent = insertion_stack.back().n;
          insertion_stack.push_back(InsertionStackElement());
          insertion_stack.back().n = result;
          return;
        }
        else {
          assert(n->left && n->right);
          insertion_stack.push_back(InsertionStackElement());
          InsertionStackElement &se = insertion_stack.back();
          se.n=n;
          n->dirty = true;
          if (!n->left->is_full()) {
            se.left=true;
            n = n->left;
          }
          else {
            se.left=false;
            n = n->right;
          }
        }
      }
    }

    Node *process_insertion_stack(bool complete = true) {
      TRACE(std::cout << "  X " << (complete ? "complete" : "continue") << ":";
            for (size_t i = 0; i < insertion_stack.size(); i++)
              std::cout << " " << insertion_stack[i].n->hash.to_string(TRACE_HASH_SIZE);
            std::cout << std::endl;);

      Node *result = insertion_stack.back().n;
      insertion_stack.pop_back();

      while (!insertion_stack.empty()) {
        InsertionStackElement &top = insertion_stack.back();
        Node *n = top.n;
        bool left = top.left;
        insertion_stack.pop_back();

        if (left)
          n->left = result;
        else
          n->right = result;

        n->dirty = true;
        n->size = n->left->size + n->right->size + 1;
        n->height = std::max(n->left->height, n->right->height) + 1;

        result = n;

        if (!complete && !result->is_full()) {
          TRACE(std::cout << "  X save " << result->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
          return result;
        }
      }

      return result;
    }

    void insert_new_leaf(Node *&root, Node *n) {
      TRACE(std::cout << " - insert_new_leaf " << n->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
      leaf_nodes.push_back(n);
      if (insertion_stack.empty() && !root)
        root = n;
      else {
        continue_insertion_stack(root, n);
        root = process_insertion_stack(false);
      }
      // TRACE(std::cout << "-----" << std::endl << this->to_string(TRACE_HASH_SIZE) << "-----" << std::endl;);
    }

  public:
    void build_from_scratch() {
      std::vector<Node*> level, next_level;

      TRACE(std::cout << "> build_from_scratch" << std::endl);
      _root = nullptr;
      for (auto &n : new_leaf_nodes)
        leaf_nodes.push_back(n);
      new_leaf_nodes.clear();
      for (auto n : leaf_nodes)
        n->parent = nullptr;
      level = leaf_nodes;

      if (level.empty())
        return;

      size_t level_no = 0;
      while (level.size() > 1) {
        TRACE(std::cout << " - " << level_no << ": ";
              for (auto node : level)
                std::cout << node->hash.to_string(TRACE_HASH_SIZE) << "(" << node->size << ") ";
              std::cout << std::endl;);

        for (size_t i=0; i < level.size(); i += 2) {
          Node* left = level[i];
          Node* right = nullptr;
          if (i + 1 < level.size())
            right = level[i+1];

          auto lparent = left->parent;
          auto rparent = right ? right->parent : nullptr;

          assert(left);
          assert(!(lparent && right && rparent && lparent != rparent));

          if (lparent) {
            assert(!right || lparent == rparent);
            next_level.push_back(lparent);
          }
          else {
            if (!right)
              next_level.push_back(left);
            else {
              assert(left && right);
              assert(!lparent && !rparent);
              auto new_parent = Node::make(left, right);
              hash(new_parent);
              next_level.push_back(new_parent);
            }
          }
        }

        std::swap(level, next_level);
        next_level.clear();
        level_no++;
      }

      assert(level.size() == 1);
      _root = level[0];
      TRACE(std::cout << " - " << level_no << ": " << _root->hash.to_string(TRACE_HASH_SIZE) << "(" << _root->size << ")" << std::endl);
      level.clear();
    }

    void insert_new_leaves(bool complete=false) {
      if (!new_leaf_nodes.empty()) {
        TRACE(std::cout << "* insert_new_leaves " << leaf_nodes.size() << " +" << new_leaf_nodes.size() << std::endl;);
        // TODO: Make this go fast when there are many leaves to insert.
        for (auto &n : new_leaf_nodes)
          insert_new_leaf(_root, n);
        new_leaf_nodes.clear();

        if (complete && !insertion_stack.empty())
          _root = process_insertion_stack();
      }
    }
  };

  static void sha256_compress(const HashT<32> &l, const HashT<32> &r, HashT<32> &out) {
    static const uint32_t constants[] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint8_t block[32 * 2];
    memcpy(&block[0], l.bytes, 32);
    memcpy(&block[32], r.bytes, 32);

    static const uint32_t s[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    uint32_t cws[64] = {0};

    for (int i = 0; i < 16; i++)
      cws[i] = be32toh(((int32_t *)block)[i]);

    for (int i = 16; i < 64; i++) {
      uint32_t t16 = cws[i - 16];
      uint32_t t15 = cws[i - 15];
      uint32_t t7 = cws[i - 7];
      uint32_t t2 = cws[i - 2];
      uint32_t s1 = (t2 >> 17 | t2 << 15) ^ ((t2 >> 19 | t2 << 13) ^ t2 >> 10);
      uint32_t s0 = (t15 >> 7 | t15 << 25) ^ ((t15 >> 18 | t15 << 14) ^ t15 >> 3);
      cws[i] = (s1 + t7 + s0 + t16);
    }

    uint32_t h[8];
    for (int i = 0; i < 8; i++)
      h[i] = s[i];

    for (int i = 0; i < 64; i++) {
      uint32_t a0 = h[0], b0 = h[1], c0 = h[2], d0 = h[3], e0 = h[4], f0 = h[5], g0 = h[6], h03 = h[7];
      uint32_t w = cws[i];
      uint32_t t1 = h03 + ((e0 >> 6 | e0 << 26) ^ ((e0 >> 11 | e0 << 21) ^ (e0 >> 25 | e0 << 7))) + ((e0 & f0) ^ (~e0 & g0)) + constants[i] + w;
      uint32_t t2 = ((a0 >> 2 | a0 << 30) ^ ((a0 >> 13 | a0 << 19) ^ (a0 >> 22 | a0 << 10))) + ((a0 & b0) ^ ((a0 & c0) ^ (b0 & c0)));
      h[0] = t1 + t2;
      h[1] = a0;
      h[2] = b0;
      h[3] = c0;
      h[4] = d0 + t1;
      h[5] = e0;
      h[6] = f0;
      h[7] = g0;
    }

    for (int i = 0; i < 8; i++)
      ((uint32_t*)out.bytes)[i] = htobe32(s[i] + h[i]);
  }

#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
// TODO: Some versions of OpenSSL don't provide SHA256_Transform?
void sha256_compress_openssl(const uint8_t *h1, const uint8_t *h2, uint8_t *out)
{
  unsigned char block[HASH_SIZE * 2];
  memcpy(&block[0], h1, HASH_SIZE);
  memcpy(&block[HASH_SIZE], h2, HASH_SIZE);

  SHA256_CTX ctx;
  if (SHA256_Init(&ctx) != 1)
    printf("SHA256_Init error");
  SHA256_Transform(&ctx, &block[0]);

  for (int i = 0; i < 8; i++)
    ((uint32_t *)out)[i] = htobe32(((uint32_t *)ctx.h)[i]);
}
#endif

  // Default tree with default hash function
  typedef HashT<32> Hash;
  typedef PathT<32, sha256_compress> Path;
  typedef TreeT<32, sha256_compress> Tree;
};
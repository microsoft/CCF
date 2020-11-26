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
      HashT<HASH_SIZE> hash;
      Direction direction;
    } Element;

    PathT(const HashT<HASH_SIZE> &leaf, std::vector<Element> &&elements)
      : leaf(leaf), elements(elements) {}
    PathT(const PathT &other);
    PathT(PathT &&other);
    PathT(std::vector<uint8_t> &bytes);

    bool verify(const HashT<HASH_SIZE> &root) const {
      HashT<HASH_SIZE> result = leaf, tmp;
      TRACE(std::cout << "> verify " << leaf.to_string(TRACE_HASH_SIZE) << std::endl);
      for (size_t i=0; i < elements.size(); i++) {
        const Element &e = elements[i];
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

    std::vector<uint8_t> serialise() const;
    operator std::vector<uint8_t>() const; // ?
    static void deserialise(std::vector<uint8_t> &bytes);

    size_t size() const { return elements.size(); }

    const HashT<HASH_SIZE>& operator[](size_t i) const { return elements[i]; }

    typedef typename std::vector<HashT<HASH_SIZE>>::const_iterator const_iterator;
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
    std::vector<Element> elements;
    size_t tgt, max; // necessary?
  };


  template<
    size_t HASH_SIZE,
    void (*HASH_FUNCTION)(const HashT<HASH_SIZE> &l, const HashT<HASH_SIZE> &r, HashT<HASH_SIZE> &out)>
  class TreeT {
  protected:

    struct Node {
      Node() :
        left(nullptr), right(nullptr),
        size(0), height(0),
        dirty(true)
       {}

      Node(const HashT<HASH_SIZE> &hash) {
        left = right = nullptr;
        this->hash = hash;
        size = height = 1;
        dirty = false;
      }

      static std::shared_ptr<Node> make(const HashT<HASH_SIZE> &hash) {
        return std::make_shared<Node>(hash);
      }

      static std::shared_ptr<Node> make(std::shared_ptr<Node> &left, std::shared_ptr<Node> &right)
      {
        assert(left && right);

        auto r = std::make_shared<Node>();
        r->left = left;
        r->right = right;
        r->dirty = true;
        r->size = left->size + right->size + 1;
        r->height = std::max(left->height, right->height) + 1;
        r->left->parent = r->right->parent = r;
        return r;
      }

      bool is_full() const {
        size_t max_size =  (1 << height) - 1;
        assert(size <= max_size);
        return size == max_size;
      }

      HashT<HASH_SIZE> hash;
      std::weak_ptr<Node> parent;
      std::shared_ptr<Node> left, right;
      size_t size, height;
      bool dirty;
    };

  public:
    TreeT() {}
    TreeT(const TreeT &other)
      : _leaf_nodes(other._leaf_nodes), _root(other._root) {}
    TreeT(TreeT &&other)
      : _leaf_nodes(other._leaf_nodes), _root(other._root) {}
    ~TreeT() {
      for (auto n : _new_leaf_nodes)
        delete n;
    }

    TreeT(std::vector<uint8_t> &bytes) {
      throw std::runtime_error("not implemented yet");
    }

    typedef HashT<HASH_SIZE> Hash;
    typedef PathT<HASH_SIZE, HASH_FUNCTION> Path;
    typedef TreeT<HASH_SIZE, HASH_FUNCTION> Tree;

    void insert_recursive(std::shared_ptr<Node> &n, std::shared_ptr<Node> &new_leaf) {
      if (!n)
        n = new_leaf;
      else {
        if (n->is_full()) {
          auto p = n->parent.lock();
          n = Node::make(n, new_leaf);
          n->parent = p;
        }
        else {
          TRACE(std::cout << " @ " << n->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
          assert(n->left && n->right);
          if (!n->left->is_full())
            insert_recursive(n->left, new_leaf);
          else
            insert_recursive(n->right, new_leaf);
          n->dirty = true;
          n->size = n->left->size + n->right->size + 1;
          n->height = std::max(n->left->height, n->right->height) + 1;
        }
      }
    }

    void insert_iterative(std::shared_ptr<Node> &root, std::shared_ptr<Node> &new_leaf) {
      typedef struct { std::shared_ptr<Node> n; bool left; } StackElement;
      static std::stack<StackElement> stack;

      if (!root) {
        root = new_leaf;
        return;
      }

      std::shared_ptr<Node> n = root;
      std::shared_ptr<Node> result = nullptr;
      while (!result)
      {
        if (n->is_full())
          result = Node::make(n, new_leaf);
        else {
          TRACE(std::cout << " @ " << n->hash.to_string(TRACE_HASH_SIZE) << std::endl;);
          assert(n->left && n->right);
          stack.push(StackElement());
          StackElement &se = stack.top();
          se.n=n;
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

      while (!stack.empty()) {
        StackElement &top = stack.top();
        std::shared_ptr<Node> &n = top.n;

        if (top.left)
          n->left = result;
        else
          n->right = result;
        n->dirty = true;
        n->size = n->left->size + n->right->size + 1;
        n->height = std::max(n->left->height, n->right->height) + 1;

        result = n;
        stack.pop();
      }

      root = result;
    }

    void insert(const Hash &hash) {
      TRACE(std::cout << "> insert " << hash.to_string(TRACE_HASH_SIZE) << std::endl;);
      _new_leaf_nodes.push_back(new Node(hash));
      statistics.num_insert++;
      TRACE(std::cout << this->to_string() << std::endl;);
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
      throw std::runtime_error("not implemented yet");
    }

    void retract_to(size_t index) {
      throw std::runtime_error("not implemented yet");
    }

    const TreeT<HASH_SIZE, HASH_FUNCTION> split(size_t index) {
      throw std::runtime_error("not implemented yet");
    }

    const Hash& operator[](size_t i) const {
      return _leaf_nodes[i].hash;
    }

    const Hash& root() {
      TRACE(std::cout << "> root" << std::endl;);
      statistics.num_root++;
      build_incremental();
      if (!_root || _root->dirty ) {
        if (_leaf_nodes.empty())
          throw std::runtime_error("empty tree does not have a root");
        hash(_root);
        assert(_root && !_root->dirty);
      }
      return _root->hash;
    }

    std::unique_ptr<const Hash> past_root(size_t index) const {
      throw std::runtime_error("not implemented yet");
    }

    std::unique_ptr<const Path> path(size_t index) {
      std::vector<typename Path::Element> elements;
      build_incremental();
      if (_root->dirty)
        hash(_root);
      auto leaf = _leaf_nodes[index];
      std::shared_ptr<Node> last = leaf;
      std::shared_ptr<Node> cur = leaf->parent.lock();
      while (cur) {
        bool last_is_left = cur->left == last;
        if (!last_is_left)
          assert (cur->right == last);
        typename Path::Element e;
        e.direction = last_is_left ? Path::PATH_RIGHT : Path::PATH_LEFT;
        e.hash = last_is_left ? cur->right->hash : cur->left->hash;
        elements.push_back(e);
        last = cur;
        cur = cur->parent.lock();
      }
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

    const Hash& leaf(size_t index) const { return _leaf_nodes[index]; }

    struct Statistics {
      size_t num_insert = 0, num_hash = 0, num_root = 0;

      std::string to_string() const {
        std::stringstream stream;
        stream << " num_insert=" << num_insert
               << " num_hash=" << num_hash
               << " num_root=" << num_root;
        return stream.str();
      }
    } statistics;

    std::string to_string(size_t num_bytes = HASH_SIZE) {
      std::stringstream stream;
      std::vector<std::shared_ptr<Node>> level, next_level;
      std::shared_ptr<Node> previous = nullptr;

      if (_leaf_nodes.empty()) {
        stream << "<EMPTY>" << std::endl;
        return stream.str();
      }

      size_t level_no = 0;
      level.push_back(_root);
      while (!level.empty()) {
        stream << level_no++ << ": ";
        for (auto n : level) {
          static const std::string dirty_hash(2*num_bytes, '?');
          stream << (n->dirty ? dirty_hash : n->hash.to_string(num_bytes));
          stream << "(" << n->size << ")";
          if (n->left) next_level.push_back(n->left);
          if (n->right) next_level.push_back(n->right);
          stream << " ";
        }
        stream << std::endl << std::flush;
        std::swap(level, next_level);
        next_level.clear();
      }

      stream << "S:" + statistics.to_string() << std::endl;

      return stream.str();
    }

  protected:
    std::vector<std::shared_ptr<Node>> _leaf_nodes;
    std::vector<Node*> _new_leaf_nodes;
    std::shared_ptr<Node> _root = nullptr;

    void hash(std::shared_ptr<Node> &n)
    {
      assert((n->left && n->right) || (!n->left && !n->right));
      if (n->left && n->left->dirty)
        hash(n->left);
      if (n->right && n->right->dirty)
        hash(n->right);
      if (n->left && n->right) {
        HASH_FUNCTION(n->left->hash, n->right->hash, n->hash);
        statistics.num_hash++;
        TRACE(std::cout << "  + h("
                        << n->left->hash.to_string(TRACE_HASH_SIZE) << ", "
                        << n->right->hash.to_string(TRACE_HASH_SIZE) << ") == "
                        << n->hash.to_string(TRACE_HASH_SIZE) << std::endl);
      }
      n->dirty = false;
    }

  public:
    void rebuild() {
      std::vector<std::shared_ptr<Node>> level, next_level;

      TRACE(std::cout << "> rebuild" << std::endl);
      _root = nullptr;
      for (auto &n : _new_leaf_nodes)
        _leaf_nodes.push_back(std::shared_ptr<Node>(n));
      _new_leaf_nodes.clear();
      for (auto n : _leaf_nodes)
        n->parent.reset();
      level = _leaf_nodes;

      size_t level_no = 0;
      while (level.size() > 1) {
        TRACE(std::cout << " - " << level_no << ": ";
              for (auto node : level)
                std::cout << node->hash.to_string(TRACE_HASH_SIZE) << "(" << node->size << ") ";
              std::cout << std::endl;);

        for (size_t i=0; i < level.size(); i += 2) {
          std::shared_ptr<Node> left = level[i];
          std::shared_ptr<Node> right = nullptr;
          if (i + 1 < level.size())
            right = level[i+1];

          auto lparent = left->parent.lock();
          auto rparent = right ? right->parent.lock() : nullptr;

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

    void build_incremental() {
      if (!_new_leaf_nodes.empty()) {
        TRACE(std::cout << "* build incremental " << _leaf_nodes.size() << " +" << _new_leaf_nodes.size() << std::endl;);
        // TODO: Make this go fast.
        for (auto &n : _new_leaf_nodes) {
          auto snode = std::shared_ptr<Node>(n);
          _leaf_nodes.push_back(snode);
          insert_recursive(_root, snode);
          // insert_iterative(_root, n);
        }
        _new_leaf_nodes.clear();
      }
    }
  };

  static void __attribute__ ((noinline)) sha256_compress(const HashT<32> &l, const HashT<32> &r, HashT<32> &out) {
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
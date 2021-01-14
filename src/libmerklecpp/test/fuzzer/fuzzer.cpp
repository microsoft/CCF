#include "../../merklecpp.h"

#include <algorithm>
#include <iostream>

typedef enum
{
  MT_INSERT = 0,
  MT_FLUSH_TO,
  MT_RETRACT_TO,
  MT_ROOT,
  MT_PAST_ROOT,
  MT_PATH,
  MT_PAST_PATH,
  MT_SERIALISE,
  MT_SERIALISE_PARTIAL,
  MT_RESET,
  MT_COPY
} Operation;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t sz)
{
  static merkle::Tree* tree = new merkle::Tree();
  size_t rem = sz;

  // std::cout << "\r min:" << tree->min_index() << " max:" <<
  // tree->max_index();

  if (sz > 0)
  {
    Operation op = (Operation)data[0];
    data++;
    rem--;

    switch (op)
    {
      case MT_INSERT:
        if (rem >= 32)
        {
          tree->insert(data);
          data += 32;
          rem -= 32;
        }
        break;
      case MT_FLUSH_TO:
        if (rem >= 8)
        {
          size_t index = *(size_t*)data;
          if (tree->min_index() <= index && index <= tree->max_index())
            tree->flush_to(index);
          data += 8;
          rem -= 8;
        }
        break;
      case MT_RETRACT_TO:
        if (rem >= 8)
        {
          size_t index = *(size_t*)data;
          if (tree->min_index() <= index && index <= tree->max_index())
            tree->retract_to(index);
          data += 8;
          rem -= 8;
        }
        break;
      case MT_ROOT:
      {
        if (!tree->empty())
          tree->root();
        break;
        case MT_PAST_ROOT:
          if (rem >= 8 && !tree->empty())
          {
            size_t index = *(size_t*)data;
            if (tree->min_index() <= index && index <= tree->max_index())
              tree->past_root(index);
            data += 8;
            rem -= 8;
          }
          break;
        case MT_PATH:
          if (rem >= 8 && !tree->empty())
          {
            size_t index = *(size_t*)data;
            if (tree->min_index() <= index && index <= tree->max_index())
            {
              auto p = tree->path(index);
              assert(p->verify(tree->root()));

              std::vector<uint8_t> buffer;
              p->serialise(buffer);
              merkle::Tree::Path p2(buffer);
              assert(*p == p2);
              assert(p->size() == p2.size());
              assert(p->leaf_index() == p2.leaf_index());
              assert(p->max_index() == p2.max_index());
            }
            data += 8;
            rem -= 8;
          }
          break;
        case MT_PAST_PATH:
          if (rem >= 16 && !tree->empty())
          {
            size_t index = *(size_t*)data;
            size_t as_of = *(size_t*)(data + 8);
            if (
              tree->min_index() <= index && index <= tree->max_index() &&
              tree->min_index() <= as_of && as_of <= tree->max_index())
            {
              if (index > as_of)
                std::swap(index, as_of);
              auto p = tree->past_path(index, as_of);
              auto past_root = tree->past_root(as_of);
              assert(p->verify(*past_root));

              std::vector<uint8_t> buffer;
              p->serialise(buffer);
              merkle::Tree::Path p2(buffer);
              assert(*p == p2);
              assert(p->size() == p2.size());
              assert(p->leaf_index() == p2.leaf_index());
              assert(p->max_index() == p2.max_index());
            }
            data += 16;
            rem -= 16;
          }
          break;
        case MT_SERIALISE:
        {
          std::vector<uint8_t> buffer;
          tree->serialise(buffer);
          assert(buffer.size() == tree->serialised_size());
          tree->deserialise(buffer);
          assert(buffer.size() == tree->serialised_size());
          break;
        }
        case MT_SERIALISE_PARTIAL:
        {
          if (rem >= 16 && !tree->empty())
          {
            size_t index = *(size_t*)data;
            size_t as_of = *(size_t*)(data + 8);
            if (
              tree->min_index() <= index && index <= tree->max_index() &&
              tree->min_index() <= as_of && as_of <= tree->max_index())
            {
              if (index > as_of)
                std::swap(index, as_of);
              std::vector<uint8_t> buffer;
              tree->serialise(index, as_of, buffer);
              assert(buffer.size() == tree->serialised_size(index, as_of));
              tree->deserialise(buffer);
              assert(buffer.size() == tree->serialised_size(index, as_of));
            }
          }
          break;
        }
        case MT_RESET:
          delete (tree);
          tree = new merkle::Tree();
          break;
        case MT_COPY:
        {
          merkle::Tree* copy = new merkle::Tree();
          *copy = *tree;
          if (!copy->empty())
            assert(copy->root() == tree->root());
          std::swap(tree, copy);
          delete (copy);
          break;
        }
        default: /* Nothing */;
      }
    }
  }

  return 0;
}

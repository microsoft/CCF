// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <set>
#include <vector>

namespace ds
{
  // Efficient representation of an ordered set of values, assuming it contains
  // some contiguous ranges. Stores a sequence of ranges, rather than individual
  // values.
  template <typename T>
  class ContiguousContainer
  {
  public:
    // Ranges are represented by their first value, and a count of additional
    // values. This disallows negative ranges
    using Range = std::pair<T, size_t>;
    using Ranges = std::vector<Range>;

    // TODO: Make this private, only const& access
    Ranges ranges;

    // Define an iterator for accessing each contained element, rather than the
    // ranges
    struct Iterator
    {
      typename Ranges::iterator it;
      size_t offset = 0;

      // clang-format off
      Iterator(typename Ranges::iterator i): it(i), offset(0) {}

      bool operator==(const Iterator& other) const { return (it == other.it && offset == other.offset); }
      bool operator!=(const Iterator& other) const { return !(*this == other); }

      Iterator& operator++()
      {
        ++offset;
        if (offset > it->second)
        {
          ++it;
          offset = 0;
        }
        return (*this);
      }
      Iterator operator++(int)
      {
        auto temp(*this);
        ++offset;
        if (offset > it->second)
        {
          ++it;
          offset = 0;
        }
        return temp;
      }
      T operator*() { return it->first + offset; }
      // clang-format on
    };

    struct ConstIterator
    {
      typename Ranges::const_iterator it;
      size_t offset = 0;

      // clang-format off
      ConstIterator(typename Ranges::const_iterator i): it(i), offset(0) {}

      bool operator==(const ConstIterator& other) const { return (it == other.it && offset == other.offset); }
      bool operator!=(const ConstIterator& other) const { return !(*this == other); }

      ConstIterator& operator++()
      {
        ++offset;
        if (offset > it->second)
        {
          ++it;
          offset = 0;
        }
        return (*this);
      }
      ConstIterator operator++(int)
      {
        auto temp(*this);
        ++offset;
        if (offset > it->second)
        {
          ++it;
          offset = 0;
        }
        return temp;
      }
      const T operator*() const { return it->first + offset; }
      // clang-format on
    };

    template <typename Iterator>
    void populate_ranges(Iterator first, Iterator end)
    {
      if (!std::is_sorted(first, end))
      {
        throw std::logic_error("Range must be sorted");
      }

      ranges.clear();
      while (first != end)
      {
        auto next = std::adjacent_find(
          first, end, [](const T& a, const T& b) { return (a + 1) != b; });
        if (next == end)
        {
          ranges.emplace_back(*first, size_t(std::distance(first, end)) - 1);
          break;
        }
        ranges.emplace_back(*first, size_t(std::distance(first, next)));
        first = std::next(next);
      }
    }

    void maybe_merge_with_following(typename Ranges::iterator it)
    {
      auto next_it = std::next(it);
      if (next_it != ranges.end())
      {
        if (it->first + it->second + 1 == next_it->first)
        {
          it->second = it->second + 1 + next_it->second;
          ranges.erase(next_it);
        }
      }
    }

    ContiguousContainer() = default;

    template <typename Iterator>
    ContiguousContainer(Iterator first, Iterator end)
    {
      populate_ranges(first, end);
    }

    ContiguousContainer(const std::set<T>& set) :
      ContiguousContainer(set.begin(), set.end())
    {}

    ContiguousContainer(std::vector<T> vec)
    {
      std::sort(vec.begin(), vec.end());
      populate_ranges(vec.begin(), vec.end());
    }

    size_t size() const
    {
      size_t n = 0;
      for (const auto& [_, additional] : ranges)
      {
        n += 1 + additional;
      }
      return n;
    }

    void insert(const T& t)
    {
      auto it = ranges.begin();
      while (it != ranges.end())
      {
        const auto& [from, additional] = *it;
        if (t < from)
        {
          // Precedes this range
          if (t + 1 == from)
          {
            // Precedes directly, extend this range by 1
            it->first = t;
            it->second++;
            if (it != ranges.begin())
            {
              maybe_merge_with_following(std::prev(it));
            }
            return;
          }
          else
          {
            // Insert new range before this
            break;
          }
        }
        else if (from <= t && t <= from + additional)
        {
          // Already present
          return;
        }
        else
        {
          // t > from + additional
          // Is it adjacent?
          if (from + additional + 1 == t)
          {
            it->second++;
            maybe_merge_with_following(it);
            return;
          }
        }
        ++it;
      }

      ranges.emplace(it, t, 0);
      return;
    }

    T first() const
    {
      return ranges.front().first;
    }

    T last() const
    {
      const auto back = ranges.back();
      return back.first + back.second;
    }

    Iterator begin()
    {
      return Iterator(ranges.begin());
    }

    ConstIterator begin() const
    {
      return ConstIterator(ranges.begin());
    }

    Iterator end()
    {
      return Iterator(ranges.end());
    }

    ConstIterator end() const
    {
      return ConstIterator(ranges.end());
    }
  };
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <numeric>
#include <vector>

namespace ds
{
  // Efficient representation of an ordered set of values, assuming it contains
  // some contiguous ranges of adjacent values. Stores a sequence of ranges,
  // rather than individual values.
  template <typename T>
  class ContiguousSet
  {
  public:
    // Ranges are represented by their first value, and a count of additional
    // values. This disallows negative ranges
    using Range = std::pair<T, size_t>;
    using Ranges = std::vector<Range>;

    // Define an iterator for accessing each contained element, rather than the
    // ranges
    template <typename RangeIt>
    struct TIterator
    {
      RangeIt it;
      size_t offset = 0;

      // clang-format off
      TIterator(RangeIt i): it(i), offset(0) {}

      bool operator==(const TIterator& other) const { return (it == other.it && offset == other.offset); }
      bool operator!=(const TIterator& other) const { return !(*this == other); }

      TIterator& operator++()
      {
        ++offset;
        if (offset > it->second)
        {
          ++it;
          offset = 0;
        }
        return (*this);
      }
      TIterator operator++(int)
      {
        auto temp(*this);
        ++(*this);
        return temp;
      }
      T operator*() const { return it->first + offset; }
      // clang-format on
    };

    using Iterator = TIterator<typename Ranges::iterator>;
    using ConstIterator = TIterator<typename Ranges::const_iterator>;

  private:
    Ranges ranges;

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

  public:
    ContiguousSet() = default;

    template <typename Iterator>
    ContiguousSet(Iterator first, Iterator end)
    {
      populate_ranges(first, end);
    }

    bool operator==(const ContiguousSet& other) const
    {
      return ranges == other.ranges;
    }

    bool operator!=(const ContiguousSet& other) const
    {
      return !(*this == other);
    }

    const Ranges& get_ranges() const
    {
      return ranges;
    }

    size_t size() const
    {
      return std::accumulate(
        ranges.begin(), ranges.end(), 0u, [](size_t n, const Range& r) {
          return n + r.second + 1;
        });
    }

    bool empty() const
    {
      return ranges.empty();
    }

    bool insert(const T& t)
    {
      auto it = ranges.begin();
      while (it != ranges.end())
      {
        const T& from = it->first;
        const T additional = it->second;
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
            return true;
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
          return false;
        }
        else
          // t > from + additional
          // Is it adjacent?
          if (from + additional + 1 == t)
        {
          it->second++;
          maybe_merge_with_following(it);
          return true;
        }
        ++it;
      }

      ranges.emplace(it, t, 0);
      return true;
    }

    bool erase(const T& t)
    {
      // TODO: These should use lower_bound, not linear search
      auto it = ranges.begin();
      while (it != ranges.end())
      {
        const T& from = it->first;
        const T additional = it->second;
        if (from <= t && t <= from + additional)
        {
          if (from == t)
          {
            if (additional == 0)
            {
              // Remove range entirely
              ranges.erase(it);
              return true;
            }
            else
            {
              // Shrink start of range
              ++it->first;
              --it->second;
              return true;
            }
          }
          else if (t == from + additional)
          {
            // Shrink end of range
            --it->second;
            return true;
          }
          else
          {
            const auto before = t - it->first - 1;
            const auto after = it->first + it->second - t - 1;

            it->second = before;

            auto next_it = std::next(it);
            ranges.emplace(next_it, t + 1, after);
            return true;
          }
        }
        ++it;
      }

      return false;
    }

    bool contains(const T& t) const
    {
      auto it = ranges.begin();
      while (it != ranges.end())
      {
        const T& from = it->first;
        const T additional = it->second;
        if (from <= t && t <= from + additional)
        {
          return true;
        }
        ++it;
      }
      return false;
    }

    void clear()
    {
      ranges.clear();
    }

    T front() const
    {
      return ranges.front().first;
    }

    T back() const
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

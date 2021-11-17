// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <numeric>
#include <vector>

namespace ds
{
  // Dense representation of an ordered set of values, assuming it contains
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
      TIterator(RangeIt i, size_t o = 0): it(i), offset(o) {}

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

    using ConstIterator = TIterator<typename Ranges::const_iterator>;

  private:
    Ranges ranges;

    template <typename It>
    void populate_ranges(It first, It end)
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

    typename Ranges::const_iterator find_internal(const T& t) const
    {
      Range estimated_range{t, 0};
      auto it = std::lower_bound(ranges.begin(), ranges.end(), estimated_range);
      if (it != ranges.end())
      {
        // If lower_bound found {t, n}, then return that result
        if (it->first == t)
        {
          return it;
        }
      }

      // else, most of the time, we found {x, n}, where x > t. Check if there
      // is a previous range, and if that contains t
      if (it != ranges.begin())
      {
        it = std::prev(it);
        const T& from = it->first;
        const T additional = it->second;
        if (from + additional >= t)
        {
          return it;
        }
      }

      return ranges.end();
    }

  public:
    ContiguousSet() = default;

    template <typename It>
    ContiguousSet(It first, It end)
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
      Range estimated_range{t, 0};
      auto it = std::lower_bound(ranges.begin(), ranges.end(), estimated_range);

      if (it != ranges.end())
      {
        const T& from = it->first;
        const T additional = it->second;
        if (from <= t && t <= from + additional)
        {
          // Already present
          return false;
        }
        else if (t < from)
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
            // Insert new range before this, in fall-through exit path
          }
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
      }

      ranges.emplace(it, t, 0);
      return true;
    }

    bool erase(const T& t)
    {
      Range estimated_range{t, 0};
      auto it = std::lower_bound(
        ranges.begin(),
        ranges.end(),
        estimated_range,
        // Custom comparator - ignore the second element
        [](const Range& left, const Range& right) { return left.first < right.first; });

      if (it != ranges.begin() && t != it->first)
      {
        it = std::prev(it);
      }

      if (it != ranges.end())
      {
        const T& from = it->first;
        const T additional = it->second;
        if (from <= t && t <= from + additional)
        {
          // Contained within this range
          if (from == t)
          {
            if (additional == 0u)
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
      }

      return false;
    }

    bool contains(const T& t) const
    {
      return find_internal(t) != end();
    }

    ConstIterator find(const T& t) const
    {
      auto it = find_internal(t);
      if (it != ranges.end())
      {
        return ConstIterator(it, t - it->first);
      }

      return end();
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

    ConstIterator begin() const
    {
      return ConstIterator(ranges.begin());
    }

    ConstIterator end() const
    {
      return ConstIterator(ranges.end());
    }
  };
}

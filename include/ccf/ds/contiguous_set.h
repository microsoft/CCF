// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#define FMT_HEADER_ONLY
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <numeric>
#include <vector>

namespace ccf::ds
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
    struct ConstIterator
    {
      using iterator_category = std::random_access_iterator_tag;
      using value_type = size_t;
      using difference_type = size_t;
      using pointer = const size_t*;
      using reference = size_t;

      using RangeIt = typename Ranges::const_iterator;

      RangeIt it;
      size_t offset = 0;

      ConstIterator(RangeIt i, size_t o = 0) : it(i), offset(o) {}

      T operator*() const
      {
        return it->first + offset;
      }

      bool operator==(const ConstIterator& other) const
      {
        return (it == other.it && offset == other.offset);
      }

      bool operator!=(const ConstIterator& other) const
      {
        return !(*this == other);
      }

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
        ++(*this);
        return temp;
      }

      ConstIterator& operator--()
      {
        if (offset == 0)
        {
          it = std::prev(it);
          offset = it->second;
        }
        else
        {
          --offset;
        }
        return (*this);
      }

      ConstIterator operator--(int)
      {
        auto temp(*this);
        --(*this);
        return temp;
      }

      ConstIterator& operator+=(difference_type n_)
      {
        if (n_ < 0)
        {
          return (*this) -= (size_t)-n_;
        }
        else
        {
          size_t n = n_;
          while (offset + n > it->second)
          {
            n -= (it->second - offset + 1);
            it = std::next(it);
            offset = 0;
          }
          offset += n;
          return (*this);
        }
      }

      ConstIterator operator+(size_t n) const
      {
        ConstIterator copy(it, offset);
        copy += n;
        return copy;
      }

      friend ConstIterator operator+(size_t n, const ConstIterator& other)
      {
        return other + n;
      }

      ConstIterator& operator-=(size_t n)
      {
        while (n > offset)
        {
          n -= (offset + 1);
          it = std::prev(it);
          offset = it->second;
        }
        offset -= n;
        return (*this);
      }

      ConstIterator operator-(size_t n) const
      {
        ConstIterator copy(it, offset);
        copy -= n;
        return copy;
      }

      difference_type operator-(const ConstIterator& other) const
      {
        if (it == other.it)
        {
          // In same range, simple diff
          return offset - other.offset;
        }
        else if (it < other.it)
        {
          return -(other - (*this));
        }
        else
        {
          // it > other.it
          // Walk from this->it to other.it, summing all of the ranges that are
          // passed
          difference_type sum = std::accumulate(
            std::reverse_iterator(it),
            std::prev(std::reverse_iterator(other.it)),
            offset + 1,
            [](difference_type acc, const auto& range) {
              return acc + range.second + 1;
            });
          sum += other.it->second - other.offset;
          return sum;
        }
      }
    };

  private:
    Ranges ranges;

    template <typename It>
    void init_from_iterators(It begin, It end)
    {
      if (!std::is_sorted(begin, end))
      {
        throw std::logic_error("Range must be sorted");
      }

      while (begin != end)
      {
        auto next = std::adjacent_find(
          begin, end, [](const T& a, const T& b) { return a + 1 != b; });
        if (next == end)
        {
          ranges.emplace_back(*begin, size_t(std::distance(begin, end)) - 1);
          break;
        }
        ranges.emplace_back(*begin, size_t(std::distance(begin, next)));
        begin = std::next(next);
      }
    }

    void init_from_iterators(
      const ConstIterator& begin, const ConstIterator& end)
    {
      // If they're in different ranges...
      if (begin.it != end.it)
      {
        // first insert the end of the initial range
        ranges.emplace_back(
          begin.it->first + begin.offset, begin.it->second - begin.offset);

        // then insert all intermediate ranges, by direct copies
        ranges.insert(ranges.end(), std::next(begin.it), end.it);

        // finally handle the final range; insert part of it if it is non-empty
        if (end.offset != 0)
        {
          ranges.emplace_back(end.it->first, end.offset - 1);
        }
      }
      else
      {
        if (begin.offset < end.offset)
        {
          ranges.emplace_back(
            begin.it->first + begin.offset, end.offset - begin.offset - 1);
        }
      }
    }

    void maybe_merge_with_following(typename Ranges::iterator it)
    {
      if (it != ranges.end())
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
    }

    void maybe_merge_with_following(typename Ranges::reverse_iterator it)
    {
      if (it != ranges.rend())
      {
        maybe_merge_with_following(std::next(it).base());
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
    ContiguousSet(It&& begin, It&& end)
    {
      init_from_iterators(std::forward<It>(begin), std::forward<It>(end));
    }

    ContiguousSet(const T& from, size_t additional)
    {
      ranges.emplace_back(from, additional);
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

    [[nodiscard]] size_t size() const
    {
      return std::accumulate(
        ranges.begin(), ranges.end(), 0u, [](size_t n, const Range& r) {
          return n + r.second + 1;
        });
    }

    [[nodiscard]] bool empty() const
    {
      return ranges.empty();
    }

    bool insert(const T& t)
    {
      // Search backwards, to find the range with the highest starting point
      // lower than this value. Offset by one, to find ranges adjacent to this
      // value. eg - if inserting 5 into [{2, 1}, {6, 2}, {10, 2}], we want to
      // find {6, 2}, and extend this range down by 1
      const Range estimated_range(t + 1, 0);
      auto it = std::lower_bound(
        ranges.rbegin(), ranges.rend(), estimated_range, std::greater<>());

      if (it != ranges.rend())
      {
        const T& from = it->first;
        const T additional = it->second;
        if (from <= t && t <= from + additional)
        {
          // Already present
          return false;
        }
        else if (from + additional + 1 == t)
        {
          // Adjacent to the end of the existing range
          it->second++;
          maybe_merge_with_following(it);
          return true;
        }
        else if (t + 1 == from)
        {
          // Precedes directly, extend this range by 1
          it->first = t;
          it->second++;
          if (it != ranges.rend())
          {
            maybe_merge_with_following(std::next(it));
          }
          return true;
        }
        // Else fall through to emplace new entry
      }

      auto emplaced_it = ranges.emplace(it.base(), t, 0);
      maybe_merge_with_following(emplaced_it);

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
        [](const Range& left, const Range& right) {
          return left.first < right.first;
        });

      // Usually this has found the iterator _after_ the range containing t, and
      // so we want std::prev(it). The only time when that is not the case are
      // if it == ranges.begin() (there is no prev), or t == it->first()
      // (lower_bound returned the correct iterator, because t is the start of a
      // range). The latter must be additionally guarded by a check that we're
      // not dereferencing an end iterator.
      if (it != ranges.begin() && (it == ranges.end() || t != it->first))
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

    void extend(const T& from, size_t additional)
    {
      for (auto n = from; n <= from + additional; ++n)
      {
        const auto b = insert(n);
      }
    }

    bool contains(const T& t) const
    {
      return find_internal(t) != end().it;
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

    ConstIterator lower_bound(const T& t) const
    {
      return std::lower_bound(begin(), end(), t);
    }

    ConstIterator upper_bound(const T& t) const
    {
      return std::upper_bound(begin(), end(), t);
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

FMT_BEGIN_NAMESPACE
template <typename T>
struct formatter<ccf::ds::ContiguousSet<T>>
{
  template <typename ParseContext>
  constexpr auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const ccf::ds::ContiguousSet<T>& v, FormatContext& ctx) const
  {
    std::vector<std::string> ranges;
    for (const auto& [from, additional] : v.get_ranges())
    {
      ranges.emplace_back(fmt::format("[{}->{}]", from, from + additional));
    }
    return format_to(
      ctx.out(),
      "{{{} values in {} ranges: {}}}",
      v.size(),
      v.get_ranges().size(),
      fmt::join(ranges, ", "));
  }
};
FMT_END_NAMESPACE

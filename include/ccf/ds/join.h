// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <algorithm>
#include <format>
#include <iterator>
#include <string_view>
#include <type_traits>
#include <utility>

namespace ccf::ds
{
  template <typename Iterator, typename Sentinel>
  struct Join
  {
    Iterator begin;
    Sentinel end;
    std::string_view separator;
  };

  // The range and separator must outlive the formatting operation.
  template <typename Iterator, typename Sentinel>
  auto join(Iterator begin, Sentinel end, std::string_view separator)
  {
    return Join<Iterator, Sentinel>{begin, end, separator};
  }

  template <typename Range>
  auto join(Range&& range, std::string_view separator)
  {
    return join(std::begin(range), std::end(range), separator);
  }
}

template <typename Iterator, typename Sentinel>
struct std::formatter<ccf::ds::Join<Iterator, Sentinel>>
  : std::formatter<std::remove_cvref_t<decltype(*std::declval<Iterator&>())>>
{
  template <typename FormatContext>
  auto format(
    const ccf::ds::Join<Iterator, Sentinel>& joined, FormatContext& ctx) const
  {
    using ElementFormatter =
      std::formatter<std::remove_cvref_t<decltype(*std::declval<Iterator&>())>>;
    auto it = joined.begin;
    auto out = ctx.out();
    if (it != joined.end)
    {
      out = ElementFormatter::format(*it, ctx);
      while (++it != joined.end)
      {
        out = std::copy(
          joined.separator.begin(), joined.separator.end(), std::move(out));
        ctx.advance_to(out);
        out = ElementFormatter::format(*it, ctx);
      }
    }
    return out;
  }
};

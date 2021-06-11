// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_bignum.h"
#include "splitid_ec.h"
#include "splitid_poly.h"

#define FMT_HEADER_ONLY
#include <fmt/format.h>

FMT_BEGIN_NAMESPACE
template <>
struct formatter<SplitIdentity::BigNum>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const SplitIdentity::BigNum& n, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), n.to_string());
  }
};

template <>
struct formatter<std::shared_ptr<SplitIdentity::BigNum>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::shared_ptr<SplitIdentity::BigNum>& n, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), n->to_string());
  }
};

template <>
struct formatter<std::vector<SplitIdentity::BigNum>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const std::vector<SplitIdentity::BigNum>& v, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), fmt::format("[{}]", fmt::join(v, ", ")));
  }
};

template <>
struct formatter<
  std::vector<std::vector<std::shared_ptr<SplitIdentity::BigNum>>>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::vector<std::vector<std::shared_ptr<SplitIdentity::BigNum>>>& vv,
    FormatContext& ctx) -> decltype(ctx.out())
  {
    return format_to(ctx.out(), fmt::format("[{}]", fmt::join(vv, ", ")));
  }
};

template <>
struct formatter<SplitIdentity::EC::Point>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const SplitIdentity::EC::Point& p, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), p.to_string());
  }
};

template <>
struct formatter<SplitIdentity::EC::CompressedPoint>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const SplitIdentity::EC::CompressedPoint& p, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    auto s = p.empty() ? "0" : SplitIdentity::to_hex(p);
    return format_to(ctx.out(), s);
  }
};

template <>
struct formatter<std::vector<SplitIdentity::EC::CompressedPoint>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::vector<SplitIdentity::EC::CompressedPoint>& p,
    FormatContext& ctx) -> decltype(ctx.out())
  {
    return format_to(ctx.out(), fmt::format("[{}]", fmt::join(p, ", ")));
  }
};

template <>
struct formatter<std::vector<std::vector<SplitIdentity::EC::CompressedPoint>>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::vector<std::vector<SplitIdentity::EC::CompressedPoint>>& vs,
    FormatContext& ctx) -> decltype(ctx.out())
  {
    return format_to(ctx.out(), fmt::format("[{}]", fmt::join(vs, ", ")));
  }
};

template <>
struct formatter<SplitIdentity::Polynomial>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const SplitIdentity::Polynomial& p, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), p.to_string());
  }
};

template <>
struct formatter<SplitIdentity::BivariatePolynomial>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const SplitIdentity::BivariatePolynomial& p, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), p.to_string());
  }
};

template <>
struct formatter<std::shared_ptr<SplitIdentity::Polynomial>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::shared_ptr<SplitIdentity::Polynomial>& p, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), p->to_string());
  }
};

template <>
struct formatter<std::shared_ptr<SplitIdentity::BivariatePolynomial>>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(
    const std::shared_ptr<SplitIdentity::BivariatePolynomial>& p,
    FormatContext& ctx) -> decltype(ctx.out())
  {
    return format_to(ctx.out(), p->to_string());
  }
};

template <>
struct formatter<SplitIdentity::SharePolynomials>
{
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const SplitIdentity::SharePolynomials& p, FormatContext& ctx)
    -> decltype(ctx.out())
  {
    return format_to(ctx.out(), p.to_string());
  }
};
FMT_END_NAMESPACE
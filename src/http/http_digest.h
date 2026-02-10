// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/crypto/md_type.h"
#include "ccf/ds/nonstd.h"

#include <charconv>
#include <string>
#include <utility>

namespace ccf::http
{
  // Helper to parse the Want-Repr-Digest request header (RFC 9530) and
  // return the best supported algorithm name and MDType. Only sha-256,
  // sha-384 and sha-512 are supported. Parsing is best-effort: malformed
  // entries are ignored. If no supported algorithm can be matched,
  // defaults to sha-256 (permitted by RFC 9530 Appendix C.2).
  static std::pair<std::string, ccf::crypto::MDType> parse_want_repr_digest(
    const std::string& want_repr_digest)
  {
    std::string best_algo;
    ccf::crypto::MDType best_md = ccf::crypto::MDType::NONE;
    int best_pref = 0;

    for (const auto& entry : ccf::nonstd::split(want_repr_digest, ","))
    {
      auto [algo, pref_sv] =
        ccf::nonstd::split_1(ccf::nonstd::trim(entry), "=");
      auto algo_name = ccf::nonstd::trim(algo);

      int pref = 0;
      auto pref_trimmed = ccf::nonstd::trim(pref_sv);
      if (!pref_trimmed.empty())
      {
        const auto [p, ec] = std::from_chars(
          pref_trimmed.data(), pref_trimmed.data() + pref_trimmed.size(), pref);
        if (ec != std::errc() || pref < 1)
        {
          continue;
        }
      }
      else
      {
        pref = 1;
      }

      ccf::crypto::MDType md = ccf::crypto::MDType::NONE;
      if (algo_name == "sha-256")
      {
        md = ccf::crypto::MDType::SHA256;
      }
      else if (algo_name == "sha-384")
      {
        md = ccf::crypto::MDType::SHA384;
      }
      else if (algo_name == "sha-512")
      {
        md = ccf::crypto::MDType::SHA512;
      }

      if (md != ccf::crypto::MDType::NONE && pref > best_pref)
      {
        best_algo = std::string(algo_name);
        best_md = md;
        best_pref = pref;
      }
    }

    if (best_md == ccf::crypto::MDType::NONE)
    {
      return std::make_pair("sha-256", ccf::crypto::MDType::SHA256);
    }

    return std::make_pair(best_algo, best_md);
  }
}

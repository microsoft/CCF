// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "kv/kv_types.h"
#include "tls/entropy.h"

#include <algorithm>
#include <nlohmann/json.hpp>

namespace ccf
{
  struct LedgerSecret
  {
    static constexpr auto MASTER_KEY_SIZE = crypto::GCM_SIZE_KEY;

    std::vector<uint8_t> master; // Referred to as "sd" in TR

    bool operator==(const LedgerSecret& other) const
    {
      return master == other.master;
    }

    LedgerSecret()
    {
      master = tls::create_entropy()->random(MASTER_KEY_SIZE);
    }

    LedgerSecret(const std::vector<uint8_t>& master_) : master(master_) {}
  };

  class LedgerSecrets
  {
  public:
    struct VersionedLedgerSecret
    {
      kv::Version version;
      LedgerSecret secret;

      bool operator==(const VersionedLedgerSecret& other) const
      {
        return version == other.version && secret == other.secret;
      }
    };
    // List of ledger secrets that are valid from a specific version to the
    // version of the next entry in the list. The last entry in the list is
    // valid for all subsequent versions.
    std::list<VersionedLedgerSecret> secrets_list;

    LedgerSecrets() = default;

    bool operator==(const LedgerSecrets& other) const
    {
      return secrets_list == other.secrets_list;
    }

    void init(kv::Version version = 1)
    {
      if (secrets_list.size() != 0)
      {
        throw std::logic_error("Ledger secrets have already been initialised!");
      }

      secrets_list.push_back({version, LedgerSecret()});
    }

    // LedgerSecret get_latest()
    // {
    //   if (secrets_list.size() == 0)
    //   {
    //     throw std::logic_error(
    //       "Could not retrieve latest ledger secret: no secret set");
    //   }
    //   return secrets_list.back().secret;
    // }

    // std::optional<LedgerSecret> get_penultimate()
    // {
    //   if (secrets_list.size() <= 1)
    //   {
    //     return std::nullopt;
    //   }
    //   return std::next(secrets_list.rbegin())->secret;
    // }

    void add_new_secret(kv::Version v, const LedgerSecret& ledger_secret)
    {
      secrets_list.push_back({v, ledger_secret});
    }

    void restore(std::list<VersionedLedgerSecret>&& restored_secrets)
    {
      if (
        secrets_list.size() >= 1 &&
        restored_secrets.back().version >= secrets_list.front().version)
      {
        throw std::logic_error(fmt::format(
          "Restored historical secrets should be before {}",
          secrets_list.front().version));
      }

      secrets_list.splice(secrets_list.begin(), std::move(restored_secrets));
    }

    std::optional<LedgerSecret> get_secret(kv::Version v)
    {
      for (auto const& s : secrets_list)
      {
        if (s.version == v)
        {
          return s.secret;
        }
      }
      LOG_FAIL_FMT("Ledger secret at version {} does not exist", v);
      return std::nullopt;
    }
  };
}
